/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	machineclientset "github.com/kubermatic/machine-controller/pkg/client/clientset/versioned"
	"github.com/kubermatic/machine-controller/pkg/client/informers/externalversions"
	machinelistersv1alpha1 "github.com/kubermatic/machine-controller/pkg/client/listers/machines/v1alpha1"
	"github.com/kubermatic/machine-controller/pkg/cloudprovider"
	cloudprovidererrors "github.com/kubermatic/machine-controller/pkg/cloudprovider/errors"
	"github.com/kubermatic/machine-controller/pkg/cloudprovider/instance"
	machinev1alpha1 "github.com/kubermatic/machine-controller/pkg/machines/v1alpha1"
	"github.com/kubermatic/machine-controller/pkg/providerconfig"
	"github.com/kubermatic/machine-controller/pkg/ssh"
	"github.com/kubermatic/machine-controller/pkg/userdata"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/json"
	"k8s.io/apimachinery/pkg/util/jsonmergepatch"
	"k8s.io/apimachinery/pkg/util/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"
	kubeinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

const (
	finalizerDeleteInstance = "machine-delete-finalizer"
)

// Controller is the controller implementation for Foo resources
type Controller struct {
	kubeClient    kubernetes.Interface
	machineClient machineclientset.Interface

	nodesLister    listerscorev1.NodeLister
	nodesSynced    cache.InformerSynced
	machinesLister machinelistersv1alpha1.MachineLister
	machinesSynced cache.InformerSynced

	workqueue workqueue.RateLimitingInterface

	sshKeypair         *ssh.KeyPair
}

// NewMachineController returns a new machine controller
func NewMachineController(
	kubeClient kubernetes.Interface,
	machineClient machineclientset.Interface,
	kubeInformerFactory kubeinformers.SharedInformerFactory,
	machineInformerFactory externalversions.SharedInformerFactory,
	sshKeypair *ssh.KeyPair) *Controller {

	nodeInformer := kubeInformerFactory.Core().V1().Nodes()
	machineInformer := machineInformerFactory.Machine().V1alpha1().Machines()

	controller := &Controller{
		kubeClient:  kubeClient,
		nodesLister: nodeInformer.Lister(),
		nodesSynced: nodeInformer.Informer().HasSynced,

		machineClient:  machineClient,
		machinesLister: machineInformer.Lister(),
		machinesSynced: machineInformer.Informer().HasSynced,

		workqueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Machines"),

		sshKeypair:         sshKeypair,
	}

	machineInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.enqueueMachine,
		UpdateFunc: func(old, new interface{}) {
			controller.enqueueMachine(new)
		},
	})

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: controller.handleObject,
		UpdateFunc: func(old, new interface{}) {
			newNode := new.(*corev1.Node)
			oldNode := old.(*corev1.Node)
			if newNode.ResourceVersion == oldNode.ResourceVersion {
				return
			}
			controller.handleObject(new)
		},
		DeleteFunc: controller.handleObject,
	})

	return controller
}

func (c *Controller) Run(threadiness int, stopCh <-chan struct{}) error {
	defer runtime.HandleCrash()
	defer c.workqueue.ShutDown()

	if ok := cache.WaitForCacheSync(stopCh, c.nodesSynced, c.machinesSynced); !ok {
		return fmt.Errorf("failed to wait for caches to sync")
	}

	for i := 0; i < threadiness; i++ {
		go wait.Until(c.runWorker, time.Second, stopCh)
	}

	<-stopCh
	return nil
}

func (c *Controller) runWorker() {
	for c.processNextWorkItem() {
	}
}

func (c *Controller) processNextWorkItem() bool {
	key, quit := c.workqueue.Get()
	if quit {
		return false
	}

	defer c.workqueue.Done(key)

	err := c.syncHandler(key.(string))
	if err == nil {
		c.workqueue.Forget(key)
		return true
	}

	utilruntime.HandleError(fmt.Errorf("%v failed with : %v", key, err))
	c.workqueue.AddRateLimited(key)

	return true
}

func (c *Controller) syncHandler(key string) error {
	listerMachine, err := c.machinesLister.Get(key)
	if err != nil {
		if errors.IsNotFound(err) {
			runtime.HandleError(fmt.Errorf("machine '%s' in work queue no longer exists", key))
			return nil
		}
		return err
	}
	machine := listerMachine.DeepCopy()

	cloudProviderConfig, err := providerconfig.GetConfig(machine.Spec.ProviderConfig)
	if err != nil {
		return fmt.Errorf("failed to get provider config: %v", err)
	}
	prov, err := cloudprovider.ForProvider(cloudProviderConfig.CloudProvider)
	if err != nil {
		return fmt.Errorf("failed to get cloud provider %q: %v", cloudProviderConfig.CloudProvider, err)
	}

	// Delete machine
	if machine.DeletionTimestamp != nil && sets.NewString(machine.Finalizers...).Has(finalizerDeleteInstance) {
		if err := prov.Delete(machine); err != nil {
			oldMachine := machine.DeepCopy()
			machine.Status.ErrorMessage = err.Error()
			machine.Status.ErrorReason = machinev1alpha1.DeleteMachineError
			if err := c.patchMachine(machine, oldMachine); err != nil {
				return fmt.Errorf("failed to patch machine %s after setting the delete error: %v", machine.Name, err)
			}
			return fmt.Errorf("failed to delete machine at cloudprovider: %v", err)
		}
		glog.V(4).Infof("Deleted machine %s at cloud provider", machine.Name)

		// Delete delete instance finalizer
		oldMachine := machine.DeepCopy()
		finalizers := sets.NewString(machine.Finalizers...)
		finalizers.Delete(finalizerDeleteInstance)
		machine.Finalizers = finalizers.List()
		if err := c.patchMachine(machine, oldMachine); err != nil {
			return fmt.Errorf("failed to patch machine %s after removing the delete instance finalizer: %v", machine.Name, err)
		}
		glog.V(4).Infof("Removed delete finalizer from machine %s", machine.Name)

		// Remove error message in case it was set
		if machine.Status.ErrorReason == machinev1alpha1.DeleteMachineError {
			oldMachine := machine.DeepCopy()
			machine.Status.ErrorReason = ""
			machine.Status.ErrorMessage = ""
			if err := c.patchMachine(machine, oldMachine); err != nil {
				return fmt.Errorf("failed to patch machine %s after removing the delete error: %v", machine.Name, err)
			}
			glog.V(4).Infof("Removed error from machine %s", machine.Name)
		}
		return nil
	}

	providerInstance, err := prov.Get(machine)
	if err != nil {
		if err == cloudprovidererrors.InstanceNotFoundErr {

			if err := prov.Validate(machine.Spec); err != nil {
				oldMachine := machine.DeepCopy()
				machine.Status.ErrorMessage = err.Error()
				machine.Status.ErrorReason = machinev1alpha1.InvalidConfigurationMachineError
				if err := c.patchMachine(machine, oldMachine); err != nil {
					return fmt.Errorf("failed to patch machine %s after setting the invalid configuration error: %v", machine.Name, err)
				}
				return fmt.Errorf("invalid provider config: %v", err)
			} else if machine.Status.ErrorReason == machinev1alpha1.InvalidConfigurationMachineError {
				oldMachine := machine.DeepCopy()
				machine.Status.ErrorReason = ""
				machine.Status.ErrorMessage = ""
				if err := c.patchMachine(machine, oldMachine); err != nil {
					return fmt.Errorf("failed to patch machine %s after removing the invalid configuration error: %v", machine.Name, err)
				}
			}
			glog.V(4).Infof("Validated machine spec of %s", machine.Name)

			providerInstance, err = c.createProviderInstance(machine, prov)
			if err != nil {
				oldMachine := machine.DeepCopy()
				machine.Status.ErrorMessage = err.Error()
				machine.Status.ErrorReason = machinev1alpha1.CreateMachineError
				if err := c.patchMachine(machine, oldMachine); err != nil {
					return fmt.Errorf("failed to patch machine %s after setting the create machine error: %v", machine.Name, err)
				}
				return fmt.Errorf("failed to create machine at cloudprovider: %v", err)
			} else if machine.Status.ErrorReason == machinev1alpha1.CreateMachineError {
				oldMachine := machine.DeepCopy()
				machine.Status.ErrorReason = ""
				machine.Status.ErrorMessage = ""
				if err := c.patchMachine(machine, oldMachine); err != nil {
					return fmt.Errorf("failed to patch machine %s after removing the create machine error: %v", machine.Name, err)
				}
			}
			glog.V(4).Infof("Created machine %s at cloud provider", machine.Name)

		} else {
			return fmt.Errorf("failed to get instance from provider: %v", err)
		}
	}

	if !sets.NewString(machine.Finalizers...).Has(finalizerDeleteInstance) {
		oldMachine := machine.DeepCopy()
		finalizers := sets.NewString(machine.Finalizers...)
		finalizers.Insert(finalizerDeleteInstance)
		machine.Finalizers = finalizers.List()
		if err := c.patchMachine(machine, oldMachine); err != nil {
			return fmt.Errorf("failed to patch machine %s after adding the delete instance finalizer: %v", machine.Name, err)
		}
		glog.V(4).Infof("Added delete finalizer to machine %s", machine.Name)
	}

	node, exists, err := c.getNode(providerInstance)
	if err != nil {
		return fmt.Errorf("failed to get node for machine %s: %v", machine.Name, err)
	}
	if exists {
		ownerRef := metav1.GetControllerOf(node)
		if ownerRef == nil {
			gv := machinev1alpha1.SchemeGroupVersion
			node.OwnerReferences = []metav1.OwnerReference{*metav1.NewControllerRef(machine, gv.WithKind("Machine"))}
			node, err = c.kubeClient.CoreV1().Nodes().Update(node)
			if err != nil {
				return fmt.Errorf("failed to update node %s after adding the owner ref: %v", node.Name, err)
			}
			glog.V(4).Infof("Added owner ref to node %s (machine %s)", node.Name, machine.Name)
		}

		if node.Spec.ConfigSource == nil && machine.Spec.ConfigSource != nil {
			node.Spec.ConfigSource = machine.Spec.ConfigSource
			node, err = c.kubeClient.CoreV1().Nodes().Update(node)
			if err != nil {
				return fmt.Errorf("failed to update node %s after setting the config source: %v", node.Name, err)
			}
			glog.V(4).Infof("Added config source to node %s (machine %s)", node.Name, machine.Name)
		}

		var labelsUpdated bool
		for k, v := range machine.Spec.Labels {
			if _, exists := node.Labels[k]; !exists {
				labelsUpdated = true
				node.Labels[k] = v
			}
		}
		if labelsUpdated {
			node, err = c.kubeClient.CoreV1().Nodes().Update(node)
			if err != nil {
				return fmt.Errorf("failed to update node %s after setting the labels: %v", node.Name, err)
			}
			glog.V(4).Infof("Added labels to node %s (machine %s)", node.Name, machine.Name)
		}

		var annotationsUpdated bool
		for k, v := range machine.Spec.Annotations {
			if _, exists := node.Annotations[k]; !exists {
				annotationsUpdated = true
				node.Annotations[k] = v
			}
		}
		if annotationsUpdated {
			node, err = c.kubeClient.CoreV1().Nodes().Update(node)
			if err != nil {
				return fmt.Errorf("failed to update node %s after setting the annotations: %v", node.Name, err)
			}
			glog.V(4).Infof("Added annotations to node %s (machine %s)", node.Name, machine.Name)
		}
	}

	return nil
}

func (c *Controller) getNode(instance instance.Instance) (node *corev1.Node, exists bool, err error) {
	nodes, err := c.nodesLister.List(labels.Everything())
	if err != nil {
		return nil, false, err
	}

	for _, instanceAddress := range instance.Addresses() {
		for _, node := range nodes {
			for _, nodeAddress := range node.Status.Addresses {
				if nodeAddress.Address == instanceAddress {
					return node.DeepCopy(), true, nil
				}
			}
		}
	}
	return nil, false, nil
}

func (c *Controller) patchMachine(newMachine, oldMachine *machinev1alpha1.Machine) error {
	currentMachine, _ := c.machineClient.MachineV1alpha1().Machines().Get(newMachine.Name, metav1.GetOptions{})
	currentJson, _ := json.Marshal(currentMachine)
	oldJson, _ := json.Marshal(oldMachine)
	newJson, _ := json.Marshal(newMachine)
	patch, _ := jsonmergepatch.CreateThreeWayJSONMergePatch(oldJson, newJson, currentJson)
	_, err := c.machineClient.MachineV1alpha1().Machines().Patch(newMachine.Name, types.MergePatchType, patch)
	return err
}

func (c *Controller) createProviderInstance(machine *machinev1alpha1.Machine, prov cloudprovider.CloudProvider) (instance.Instance, error) {
	userdataProvider, err := userdata.ForOS("coreos")
	if err != nil {
		return nil, fmt.Errorf("failed to userdata provider for coreos: %v", err)
	}

	kubeconfig, err := c.createBootstrapKubeconfig(machine.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap kubeconfig: %v", err)
	}

	data, err := userdataProvider.UserData(machine.Spec, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed get userdata: %v", err)
	}
	glog.Info("=================== BEGIN USERDATA ===================")
	glog.Info(data)
	glog.Info("=================== END USERDATA ===================")

	glog.Infof("creating instance...")
	return prov.Create(machine, data, c.sshKeypair.PublicKey)
}

func (c *Controller) enqueueMachine(obj interface{}) {
	var key string
	var err error
	if key, err = cache.MetaNamespaceKeyFunc(obj); err != nil {
		runtime.HandleError(err)
		return
	}
	c.workqueue.AddRateLimited(key)
}

func (c *Controller) handleObject(obj interface{}) {
	var object metav1.Object
	var ok bool
	if object, ok = obj.(metav1.Object); !ok {
		tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			runtime.HandleError(fmt.Errorf("error decoding object, invalid type"))
			return
		}
		object, ok = tombstone.Obj.(metav1.Object)
		if !ok {
			runtime.HandleError(fmt.Errorf("error decoding object tombstone, invalid type"))
			return
		}
		glog.V(4).Infof("Recovered deleted object '%s' from tombstone", object.GetName())
	}
	glog.V(4).Infof("Processing object: %s", object.GetName())
	if ownerRef := metav1.GetControllerOf(object); ownerRef != nil {
		if ownerRef.Kind != "Machine" {
			return
		}
		machine, err := c.machinesLister.Get(ownerRef.Name)
		if err != nil {
			glog.V(4).Infof("ignoring orphaned object '%s' of machine '%s'", object.GetSelfLink(), ownerRef.Name)
			return
		}

		c.enqueueMachine(machine)
		return
	}
}

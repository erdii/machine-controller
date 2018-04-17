package vsphere

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"text/template"

	"github.com/golang/glog"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

const (
	snapshotName     = "machine-controller"
	snapshotDesc     = "Snapshot created by machine-controller"
	localTempDir     = "/tmp"
	metaDataTemplate = `instance-id: {{ .InstanceID}}
	local-hostname: {{ .Hostname }}`
)

var errSnapshotNotFound = errors.New("no snapshot with given name found")

func CreateLinkClonedVm(vmName, vmImage, datacenter, clusterName string, cpus int32, memoryMB int64, client *govmomi.Client) (string, error) {
	f := find.NewFinder(client.Client, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dc, err := f.Datacenter(ctx, datacenter)
	if err != nil {
		return "", err
	}
	f.SetDatacenter(dc)

	templateVm, err := f.VirtualMachine(ctx, vmImage)
	if err != nil {
		return "", err
	}

	glog.V(3).Infof("Template VM ref is %+v", templateVm)
	datacenterFolders, err := dc.Folders(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get datacenter folders: %v", err)
	}

	// Create snapshot of the template VM if not already snapshotted.
	snapshot, err := findSnapshot(templateVm, ctx, snapshotName)
	if err != nil {
		if err != errSnapshotNotFound {
			return "", fmt.Errorf("failed to find snapshot: %v", err)
		}
		snapshot, err = createSnapshot(ctx, templateVm, snapshotName, snapshotDesc)
		if err != nil {
			return "", fmt.Errorf("failed to create snapshot: %v", err)
		}
	}

	clsComputeRes, err := f.ClusterComputeResource(ctx, clusterName)
	if err != nil {
		return "", fmt.Errorf("failed to get cluster %s: %v", clusterName, err)
	}
	glog.V(3).Infof("Cluster is %+v", clsComputeRes)

	resPool, err := clsComputeRes.ResourcePool(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get ressource pool: %v", err)
	}
	glog.V(3).Infof("Cluster resource pool is %+v", resPool)

	if resPool == nil {
		return "", fmt.Errorf("no resource pool found for cluster %s", clusterName)
	}

	resPoolRef := resPool.Reference()
	snapshotRef := snapshot.Reference()

	diskUuidEnabled := true
	cloneSpec := &types.VirtualMachineCloneSpec{
		Config: &types.VirtualMachineConfigSpec{
			Flags: &types.VirtualMachineFlagInfo{
				DiskUuidEnabled: &diskUuidEnabled,
			},
			NumCPUs:  cpus,
			MemoryMB: memoryMB,
		},
		Location: types.VirtualMachineRelocateSpec{
			Pool:         &resPoolRef,
			DiskMoveType: "createNewChildDiskBacking",
		},
		Snapshot: &snapshotRef,
	}

	// Create a link cloned VM from the template VM's snapshot
	clonedVmTask, err := templateVm.Clone(ctx, datacenterFolders.VmFolder, vmName, *cloneSpec)
	if err != nil {
		return "", err
	}

	clonedVmTaskInfo, err := clonedVmTask.WaitForResult(ctx, nil)
	if err != nil {
		return "", err
	}

	clonedVm := clonedVmTaskInfo.Result.(object.Reference)

	return clonedVm.Reference().Value, nil
}

func createSnapshot(ctx context.Context, vm *object.VirtualMachine, snapshotName string, snapshotDesc string) (object.Reference, error) {
	task, err := vm.CreateSnapshot(ctx, snapshotName, snapshotDesc, false, false)
	if err != nil {
		return nil, err
	}

	taskInfo, err := task.WaitForResult(ctx, nil)
	if err != nil {
		return nil, err
	}
	glog.Infof("taskInfo.Result is %s", taskInfo.Result)
	return taskInfo.Result.(object.Reference), nil
}

func findSnapshot(vm *object.VirtualMachine, ctx context.Context, name string) (object.Reference, error) {
	var moVirtualMachine mo.VirtualMachine

	err := vm.Properties(ctx, vm.Reference(), []string{"snapshot"}, &moVirtualMachine)
	if err != nil {
		return nil, err
	}

	snapshotCandidates := []object.Reference{}
	for _, snapshotTree := range moVirtualMachine.Snapshot.RootSnapshotList {
		addMatchingSnapshotToList(&snapshotCandidates, snapshotTree, name)
	}

	switch len(snapshotCandidates) {
	case 0:
		return nil, errSnapshotNotFound
	case 1:
		return snapshotCandidates[0], nil
	default:
		glog.Warningf("VM %s seems to have more than one snapshots with name %s. Using a random snapshot.", vm, name)
		return snapshotCandidates[0], nil
	}
}

// VirtualMachineSnapshotTree is a tree (As the name suggests) so we need to use recursion to get all elements
func addMatchingSnapshotToList(list *[]object.Reference, tree types.VirtualMachineSnapshotTree, name string) {
	for _, childTree := range tree.ChildSnapshotList {
		addMatchingSnapshotToList(list, childTree, name)
	}
	if tree.Name == name || tree.Snapshot.Value == name {
		*list = append(*list, &tree.Snapshot)
	}
}

func uploadAndAttachISO(f *find.Finder, vmRef *object.VirtualMachine, localIsoFilePath, datastoreName string, client *govmomi.Client) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	datastore, err := f.Datastore(ctx, datastoreName)
	if err != nil {
		return err
	}
	p := soap.DefaultUpload
	remoteIsoFilePath := fmt.Sprintf("%s/%s", vmRef.Name(), "cloud-init.iso")
	glog.V(3).Infof("Uploading userdata ISO to datastore %+v, destination iso is %s\n", datastore, remoteIsoFilePath)
	err = datastore.UploadFile(ctx, localIsoFilePath, remoteIsoFilePath, &p)
	if err != nil {
		return err
	}
	glog.V(3).Infof("Uploaded ISO file %s", localIsoFilePath)

	// Find the cd-rom devide and insert the cloud init iso file into it.
	devices, err := vmRef.Device(ctx)
	if err != nil {
		return err
	}

	// passing empty cd-rom name so that the first one gets returned
	cdrom, err := devices.FindCdrom("")
	cdrom.Connectable.StartConnected = true
	if err != nil {
		return err
	}
	iso := datastore.Path(remoteIsoFilePath)
	return vmRef.EditDevice(ctx, devices.InsertIso(cdrom, iso))
}

func getDatacenterFinder(datacenter string, client *govmomi.Client) (*find.Finder, error) {
	finder := find.NewFinder(client.Client, true)
	dc, err := finder.Datacenter(context.TODO(), datacenter)
	if err != nil {
		return nil, fmt.Errorf("failed to get vsphere datacenter: %v", err)
	}
	finder.SetDatacenter(dc)
	return finder, nil
}

func generateLocalUserdataIso(userdata, name string) (string, error) {
	// We must create a directory, because the iso-generation commands
	// take a directory as input
	userdataDir, err := ioutil.TempDir(localTempDir, name)
	if err != nil {
		return "", fmt.Errorf("failed to create local temp directory for userdata at %s: %v", userdataDir, err)
	}
	defer func() {
		err := os.RemoveAll(userdataDir)
		if err != nil {
			utilruntime.HandleError(fmt.Errorf("error cleaning up local userdata tempdir %s: %v", userdataDir, err))
		}
	}()

	userdataFilePath := fmt.Sprintf("%s/user-data", userdataDir)
	metadataFilePath := fmt.Sprintf("%s/meta-data", userdataDir)
	isoFilePath := fmt.Sprintf("%s/%s.iso", localTempDir, name)

	metadataTmpl, err := template.New("metadata").Parse(metaDataTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse metadata template: %v", err)
	}
	metadata := &bytes.Buffer{}
	templateContext := struct {
		InstanceID string
		Hostname   string
	}{
		InstanceID: name,
		Hostname:   name,
	}
	err = metadataTmpl.Execute(metadata, templateContext)
	if err != nil {
		return "", fmt.Errorf("failed to render metadata: %v", err)
	}

	err = ioutil.WriteFile(userdataFilePath, []byte(userdata), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to locally write userdata file to %s: %v", userdataFilePath, err)
	}

	err = ioutil.WriteFile(metadataFilePath, metadata.Bytes(), 0644)
	if err != nil {
		return "", fmt.Errorf("failed to locally write metadata file to %s: %v", userdataFilePath, err)
	}

	command := "genisoimage"
	args := []string{"-o", isoFilePath, "-volid", "cidata", "-joliet", "-rock", userdataDir}
	cmd := exec.Command(command, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("error executing command `%s %s`: output: `%s`, error: `%v`", command, args, string(output), err)
	}

	return isoFilePath, nil
}

func removeFloppyDevice(virtualMachine *object.VirtualMachine) error {
	vmDevices, err := virtualMachine.Device(context.TODO())
	if err != nil {
		return fmt.Errorf("failed to get device list: %v", err)
	}

	// If there is more than one floppy device attached, you will simply get the first one. We
	// assume this wont happen.
	floppyDevice, err := vmDevices.FindFloppy("")
	if err != nil {
		if err.Error() == "no floppy device found" {
			return nil
		}
		return fmt.Errorf("failed to find floppy: %v", err)
	}

	err = virtualMachine.RemoveDevice(context.TODO(), false, floppyDevice)
	if err != nil {
		return fmt.Errorf("failed to remove floppy device: %v", err)
	}

	return nil
}
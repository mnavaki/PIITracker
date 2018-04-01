## PIITracker

PIITracker tracks Personally Identifiable Information (PII) throughtout the system. 
PIITracker utelizes the taint engine in `PANDA` e.g. taint2 plugin. PIITracker is based off PANDA commit 
5606090f575a25e4de83af4e3c6a7f6f70050bf7.

## Install

To install the PANDA component of PIITracker, install all the required libraries
to install PANDA as detailed in [README_PANDA.md](panda/README_PANDA.md). 

Once you have installed all the dependencies run the install script, found at
[qemu/build.sh](panda/qemu/build.sh).


## PIITracker Plugin

PIITracker monitors specific function/system calls to introduce taint, and then utilizes the taint2 plugin to track PII.

This plugin can be found in the panda_plugins directory under the folder, PIITracker.


## Running PIITracker

We can run PIITracker in two modes: 1. Real time 2. Record/Replay, but we only recommand using PIITracker in Record/Replay mode.

### Record/Replay

In this mode, we first record PANDA traces and then replay that with PIITracker plugin loaded.
    
    2.1 Record
        2.1.1 Start VM:
            $cd qemu/
            $sudo ./i386-softmmu/qemu-system-i386 -hda PATH_TO_VM_IMG/win7.qcow -m 1G --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -vnc :1
        2.1.2 Start recording
            (qemu) begin_record record_name
        2.1.3 Stop recording
            (qemu) stop_record
        2.1.4 Exit QEMU
            (qemu) quit
    2.2 Replay
        2.2.1 Start VM
            $cd qemu/
            $sudo ./i386-softmmu/qemu-system-i386 -replay record_name -m 1G --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda PIITracker:pname=pocess.exe,taint_enable=true

### Command Line Options

PIITracker plugin provides two input arguments:

**1. pname**
              
    To specify the target process(es), to track its activities, 'pname' argument should be used.

        $sudo ./i386-softmmu/qemu-system-i386 -replay record_name -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda PIITracker:pname=pocess1.exe-pocess2.exe

    filters out the results for processes with pname=pocess1.exe and pname=pocess2.exe.

**2. taint_enable**
    
    Taint engine has been disabled by default. If you need to enable taint engine, you only need to initiate *taint_enable* argument in the command line by "true". For example, the following command

        $sudo ./i386-softmmu/qemu-system-i386 -replay record_name -m 4048 --monitor stdio -netdev user,id=net0 -device e1000,netdev=net0 -panda PIITracker:pname=pocess.exe,taint_enable=true
        
    enables taint engine and filters out the result for pocess.exe.



## PIITracker Outputs

PIITracker plugin generates two outputs under the following directory:

        PATH_TO_PIITracker_DIR/panda/qemu/
 
These two outputs are as follows:
 
        1. PIITracker.log
           It used for debugging purposes.
           
        2. PIITracker.taint
           The actual output of PIITracker. If PIITracker catches that the target process sends any PII over the network, it will report it here.

## Publications

* Meisam Navaki Arefi, Geoffrey Alexander, and Jedidiah R. Crandall. **PIITracker: Automatic Tracking of Personally Identifiable Information in Windows**. In the Proceedings of 11th European Workshop on Systems Security (EUROSEC 2018). Porto, Portugal. April 2018.

## License

GPLv2


import {log} from "./logger";
import {strace} from "./strace";


let soName="libdumper.so";
let once=false;
export let straceInject={
    start:function (){
        let module = Process.findModuleByName(soName);
        if (module!==undefined){
            trace()
            return;
        }
        let open = Module.findExportByName(null, "open");
        if (open!=null){
            Interceptor.attach(open,{
                onEnter:function (args){
                    let path = args[0].readCString();
                    // log("path:"+path)
                    // @ts-ignore
                    if (path.indexOf(soName)!==-1){
                        this.hook=true;
                    }
                },
                onLeave:function (ret){
                    if (this.hook){
                        trace();
                    }
                }
            })
        }
    }
}

function trace(){

    let module = Process.findModuleByName(soName);
    log("module:"+module)
    if (module===undefined
    || module===null){
        setTimeout(function (){
            trace();
        },100);
    }
    log("module:"+module.base)
    if (once){
        return
    }
    once=true;
    strace.start(soName,0x539f8,0x70);
}


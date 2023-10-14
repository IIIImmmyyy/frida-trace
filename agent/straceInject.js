import {log} from "./logger";
import {strace} from "./strace";


let soName="libil2cpp.so";
let once=false;
export let straceInject={
    start:function (){
        if (Process.pointerSize === 8) {
            let linker = Process.findModuleByName("linker64");
            Interceptor.attach(linker.base.add(0x4ecd0), {
                onEnter: function (args) {
                    let loadSo = args[3].readCString();
                    if (loadSo.indexOf("libil2cpp.so") !== -1) {
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
    strace.start(soName,0x181ba08,0x1e8);
}


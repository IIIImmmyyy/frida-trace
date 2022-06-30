import {log} from "./logger";
import {strace} from "./strace";
import {straceInject} from "./straceInject";


setImmediate(main)

function main() {
    straceInject.start();
}




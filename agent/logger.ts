const DEBUG: boolean = false;

export function log(msg: string): void {
    if (DEBUG) {
        log4Android(msg);
    } else {
        console.log(msg);
    }
}

export function log4Android(msg: string): void {
    let log = "android.util.Log";
    let log_cls = Java.use(log);
    log_cls.i("Dumper", msg);
}
export function  logHHex(pointer :NativePointer) :void {
    console.log(hexdump(pointer, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
    }));
}

export function logColor(message: string, type: number): void {
    if (DEBUG) {
        log4Android(message);
        return;
    }
    if (type == undefined) {
        log(message)
        return;
    }
    switch (type) {
        case LogColor.WHITE:
            log(message);
            break;
        case LogColor.RED:
            console.error(message);
            break;
        case LogColor.YELLOW:
            console.warn(message);
            break;
        default:
            console.log("\x1b[" + type + "m" + message + "\x1b[0m");
            break;

    }

}

export var LogColor = {
    WHITE: 0,
    RED: 1,
    YELLOW: 3,
    C31: 31,
    C32: 32,
    C33: 33,
    C34: 34,
    C35: 35,
    C36: 36,
    C41: 41,
    C42: 42,
    C43: 43,
    C44: 44,
    C45: 45,
    C46: 46,
    C90: 90,
    C91: 91,
    C92: 92,
    C93: 93,
    C94: 94,
    C95: 95,
    C96: 96,
    C97: 97,
    C100: 100,
    C101: 101,
    C102: 102,
    C103: 103,
    C104: 104,
    C105: 105,
    C106: 106,
    C107: 107
}








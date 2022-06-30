(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (setImmediate){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const straceInject_1 = require("./straceInject");
setImmediate(main);
function main() {
    straceInject_1.straceInject.start();
}
}).call(this)}).call(this,require("timers").setImmediate)

},{"./straceInject":4,"timers":6}],2:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.LogColor = exports.logColor = exports.logHHex = exports.log4Android = exports.log = void 0;
const DEBUG = false;
function log(msg) {
    if (DEBUG) {
        log4Android(msg);
    }
    else {
        console.log(msg);
    }
}
exports.log = log;
function log4Android(msg) {
    let log = "android.util.Log";
    let log_cls = Java.use(log);
    log_cls.i("Dumper", msg);
}
exports.log4Android = log4Android;
function logHHex(pointer) {
    console.log(hexdump(pointer, {
        offset: 0,
        length: 64,
        header: true,
        ansi: true
    }));
}
exports.logHHex = logHHex;
function logColor(message, type) {
    if (DEBUG) {
        log4Android(message);
        return;
    }
    if (type == undefined) {
        log(message);
        return;
    }
    switch (type) {
        case exports.LogColor.WHITE:
            log(message);
            break;
        case exports.LogColor.RED:
            console.error(message);
            break;
        case exports.LogColor.YELLOW:
            console.warn(message);
            break;
        default:
            console.log("\x1b[" + type + "m" + message + "\x1b[0m");
            break;
    }
}
exports.logColor = logColor;
exports.LogColor = {
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
};
},{}],3:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.strace = void 0;
const logger_1 = require("./logger");
let moduleBase;
let isFirstIn = true;
let pre_regs;
let infoMap = new Map();
let detailInsMap = new Map();
exports.strace = {
    start: function (soname, addr, size) {
        let module = Process.findModuleByName(soname);
        moduleBase = module.base;
        (0, logger_1.log)(JSON.stringify(module));
        Interceptor.attach(moduleBase.add(addr), {
            onEnter: function (args) {
                this.pid = Process.getCurrentThreadId();
                //看下结构体的值
                Stalker.follow(this.pid, {
                    transform: function (iterator) {
                        let lastInfo;
                        const instruction = iterator.next();
                        let startAddress = instruction.address;
                        // log("startAddress:" + startAddress + " base:" + module.base + " offset:" + offset);
                        if (size === 0) {
                            size = module.size;
                            addr = 0;
                        }
                        const isModuleCode = startAddress.compare(moduleBase.add(addr)) >= 0 &&
                            startAddress.compare(moduleBase.add(addr).add(size)) < 0;
                        do {
                            if (isModuleCode) {
                                let s = parserNextAddr(instruction);
                                let address = instruction.address;
                                let offset = address - moduleBase;
                                let lastInfo = s.toString(16) + "\t\t" + instruction;
                                detailInsMap.set(offset, JSON.stringify(instruction));
                                infoMap.set(offset, lastInfo);
                                iterator.putCallout(function (context) {
                                    let regs = JSON.stringify(context);
                                    if (isFirstIn) {
                                        isFirstIn = false;
                                        //保存寄存器
                                        pre_regs = formatArm64Regs(context);
                                    }
                                    else {
                                        //打印的实际是上一次的 这样延迟一次可以打印出寄存器变化
                                        let pcReg = getPcReg(pre_regs);
                                        let offset = Number(pcReg) - moduleBase;
                                        let logInfo = infoMap.get(offset);
                                        let detailIns = detailInsMap.get(offset);
                                        // log("detailIns:"+detailIns)
                                        let entity = isRegsChange(context, detailIns);
                                        (0, logger_1.logColor)(logInfo + " ; " + entity.info, entity.color);
                                    }
                                });
                            }
                            iterator.keep();
                        } while (iterator.next() != null);
                    },
                });
            },
            onLeave: function (ret) {
                // libtprt.saveStringMapTofile();
                Stalker.unfollow(this.pid);
                (0, logger_1.log)("ret:" + ret);
            }
        });
    }
};
function parserNextAddr(ins) {
    let s = JSON.stringify(ins);
    let address = ins.address;
    // log("address:"+address)
    let offset = address - moduleBase;
    let s1 = (offset).toString(16);
    let entity = {};
    entity.address = offset;
    return s1;
}
const byteToHex = [];
for (let n = 0; n <= 0xff; ++n) {
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}
function hex(arrayBuffer) {
    const buff = new Uint8Array(arrayBuffer);
    const hexOctets = [];
    for (let i = 0; i < buff.length; ++i)
        hexOctets.push(byteToHex[buff[i]]);
    return hexOctets.join("");
}
function formatArm64Regs(context) {
    let regs = [];
    regs.push(context.x0);
    regs.push(context.x1);
    regs.push(context.x2);
    regs.push(context.x3);
    regs.push(context.x4);
    regs.push(context.x5);
    regs.push(context.x6);
    regs.push(context.x7);
    regs.push(context.x8);
    regs.push(context.x9);
    regs.push(context.x10);
    regs.push(context.x11);
    regs.push(context.x12);
    regs.push(context.x13);
    regs.push(context.x14);
    regs.push(context.x15);
    regs.push(context.x16);
    regs.push(context.x17);
    regs.push(context.x18);
    regs.push(context.x19);
    regs.push(context.x20);
    regs.push(context.x21);
    regs.push(context.x22);
    regs.push(context.x23);
    regs.push(context.x24);
    regs.push(context.x25);
    regs.push(context.x26);
    regs.push(context.x27);
    regs.push(context.x28);
    regs.push(context.fp);
    regs.push(context.lr);
    regs.push(context.sp);
    regs.push(context.pc);
    return regs;
}
function getPcReg(regs) {
    return regs[32];
}
function isRegsChange(context, ins) {
    let currentRegs = formatArm64Regs(context);
    let logInfo = "";
    for (let i = 0; i < 32; i++) {
        if (i === 30) {
            continue;
        }
        let preReg = pre_regs[i];
        let currentReg = currentRegs[i];
        if (Number(preReg) !== Number(currentReg)) {
            if (logInfo === "") {
                //尝试读取string
                let changeString = "";
                try {
                    let nativePointer = new NativePointer(currentReg);
                    changeString = nativePointer.readCString();
                }
                catch (e) {
                    changeString = "";
                }
                if (changeString !== "") {
                    currentReg = currentReg + "   (" + changeString + ")";
                }
                logInfo = "\t " + getRegsString(i) + " = " + preReg + " --> " + currentReg;
            }
            else {
                logInfo = logInfo + "\t " + getRegsString(i) + " = " + preReg + " --> " + currentReg;
            }
        }
    }
    //打印PC寄存器
    let parse = JSON.parse(ins);
    let mnemonic = parse.mnemonic; //补充str
    if (mnemonic === "str") {
        let strParams = getStrParams(parse, currentRegs);
        logInfo = logInfo + strParams;
    }
    else if (mnemonic === "cmp") {
        let cmpParams = getCmpParams(parse, currentRegs);
        logInfo = logInfo + cmpParams;
    }
    else if (mnemonic === "b.gt" || mnemonic === "b.le" || mnemonic === "b.eq" || mnemonic === "b.ne" || mnemonic === "b") {
        // log(ins)
        let bgtAddr = getbgtAddr(parse, currentRegs);
        logInfo = logInfo + bgtAddr;
    }
    let entity = {};
    entity.info = logInfo;
    let address = parse.address;
    if (lastAddr === undefined) {
        entity.color = getColor();
        lastAddr = address;
    }
    else {
        let number = address - lastAddr;
        if (number === 0x4) {
            entity.color = getColor();
        }
        else {
            currentIndex++;
            entity.color = getColor();
        }
        lastAddr = address;
    }
    pre_regs = currentRegs;
    return entity;
}
let lastAddr = undefined;
let currentIndex = 0;
function getColor() {
    if (currentIndex > 1) {
        currentIndex = 0;
    }
    if (currentIndex === 0) {
        return logger_1.LogColor.C35;
    }
    else if (currentIndex === 1) {
        return logger_1.LogColor.C97;
    }
    else if (currentIndex === 2) {
        return logger_1.LogColor.C97;
    }
}
function getRegsString(index) {
    let reg;
    if (index === 31) {
        reg = "sp";
    }
    else {
        reg = "x" + index;
    }
    return reg;
}
function getbgtAddr(parser, currentRegs) {
    let bgtAddr = "";
    let operands = parser.operands;
    for (let i = 0; i < operands.length; i++) {
        let operand = operands[i];
        if (operand.type === "imm") {
            let value = operand.value;
            let number = value - moduleBase;
            bgtAddr = "\t block addr:" + number.toString(16);
            break;
        }
    }
    return bgtAddr;
}
function getStrParams(parser, currentRegs) {
    let operands = parser.operands;
    for (let i = 0; i < operands.length; i++) {
        let operand = operands[i];
        if (operand.type === "reg") {
            //获取value
            let value = operand.value;
            if (value === "wzr") {
                return "\t " + "str = 0";
            }
            else {
                let replace = value.replace("w", "");
                let index = replace.replace("x", "");
                let index_reg = currentRegs[index];
                let changeString = "";
                try {
                    let nativePointer = new NativePointer(index_reg);
                    changeString = nativePointer.readCString();
                }
                catch (e) {
                    changeString = "";
                }
                //读取值
                if (changeString !== "") {
                    index_reg = index_reg + "   (" + changeString + ")";
                }
                return "\t " + "str = " + index_reg;
            }
        }
    }
}
function getCmpParams(parser, currentRegs) {
    let operands = parser.operands;
    let cmpInfo = "";
    for (let i = 0; i < operands.length; i++) {
        let operand = operands[i];
        if (operand.type === "reg") {
            let value = operand.value;
            let replace = value.replace("w", "");
            let index = replace.replace("x", "");
            let index_reg = currentRegs[index];
            let changeString = "";
            try {
                let nativePointer = new NativePointer(index_reg);
                changeString = nativePointer.readCString();
            }
            catch (e) {
                changeString = "";
            }
            //读取值
            if (changeString !== "") {
                index_reg = index_reg + "   (" + changeString + ")";
            }
            cmpInfo = cmpInfo + "\t " + value + " = " + index_reg;
        }
    }
    return cmpInfo;
}
},{"./logger":2}],4:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.straceInject = void 0;
const logger_1 = require("./logger");
const strace_1 = require("./strace");
let soName = "libdumper.so";
let once = false;
exports.straceInject = {
    start: function () {
        let module = Process.findModuleByName(soName);
        if (module !== undefined) {
            trace();
            return;
        }
        let open = Module.findExportByName(null, "open");
        if (open != null) {
            Interceptor.attach(open, {
                onEnter: function (args) {
                    let path = args[0].readCString();
                    // log("path:"+path)
                    // @ts-ignore
                    if (path.indexOf(soName) !== -1) {
                        this.hook = true;
                    }
                },
                onLeave: function (ret) {
                    if (this.hook) {
                        trace();
                    }
                }
            });
        }
    }
};
function trace() {
    let module = Process.findModuleByName(soName);
    (0, logger_1.log)("module:" + module);
    if (module === undefined
        || module === null) {
        setTimeout(function () {
            trace();
        }, 100);
    }
    (0, logger_1.log)("module:" + module.base);
    if (once) {
        return;
    }
    once = true;
    strace_1.strace.start(soName, 0x539f8, 0x70);
}
},{"./logger":2,"./strace":3}],5:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],6:[function(require,module,exports){
(function (setImmediate,clearImmediate){(function (){
var nextTick = require('process/browser.js').nextTick;
var apply = Function.prototype.apply;
var slice = Array.prototype.slice;
var immediateIds = {};
var nextImmediateId = 0;

// DOM APIs, for completeness

exports.setTimeout = function() {
  return new Timeout(apply.call(setTimeout, window, arguments), clearTimeout);
};
exports.setInterval = function() {
  return new Timeout(apply.call(setInterval, window, arguments), clearInterval);
};
exports.clearTimeout =
exports.clearInterval = function(timeout) { timeout.close(); };

function Timeout(id, clearFn) {
  this._id = id;
  this._clearFn = clearFn;
}
Timeout.prototype.unref = Timeout.prototype.ref = function() {};
Timeout.prototype.close = function() {
  this._clearFn.call(window, this._id);
};

// Does not start the time, just sets up the members needed.
exports.enroll = function(item, msecs) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = msecs;
};

exports.unenroll = function(item) {
  clearTimeout(item._idleTimeoutId);
  item._idleTimeout = -1;
};

exports._unrefActive = exports.active = function(item) {
  clearTimeout(item._idleTimeoutId);

  var msecs = item._idleTimeout;
  if (msecs >= 0) {
    item._idleTimeoutId = setTimeout(function onTimeout() {
      if (item._onTimeout)
        item._onTimeout();
    }, msecs);
  }
};

// That's not how node.js implements it but the exposed api is the same.
exports.setImmediate = typeof setImmediate === "function" ? setImmediate : function(fn) {
  var id = nextImmediateId++;
  var args = arguments.length < 2 ? false : slice.call(arguments, 1);

  immediateIds[id] = true;

  nextTick(function onNextTick() {
    if (immediateIds[id]) {
      // fn.call() is faster so we optimize for the common use-case
      // @see http://jsperf.com/call-apply-segu
      if (args) {
        fn.apply(null, args);
      } else {
        fn.call(null);
      }
      // Prevent ids from leaking
      exports.clearImmediate(id);
    }
  });

  return id;
};

exports.clearImmediate = typeof clearImmediate === "function" ? clearImmediate : function(id) {
  delete immediateIds[id];
};
}).call(this)}).call(this,require("timers").setImmediate,require("timers").clearImmediate)

},{"process/browser.js":5,"timers":6}]},{},[1])
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9pbmRleC50cyIsImFnZW50L2xvZ2dlci50cyIsImFnZW50L3N0cmFjZS5qcyIsImFnZW50L3N0cmFjZUluamVjdC5qcyIsIm5vZGVfbW9kdWxlcy9wcm9jZXNzL2Jyb3dzZXIuanMiLCJub2RlX21vZHVsZXMvdGltZXJzLWJyb3dzZXJpZnkvbWFpbi5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7OztBQ0VBLGlEQUE0QztBQUc1QyxZQUFZLENBQUMsSUFBSSxDQUFDLENBQUE7QUFFbEIsU0FBUyxJQUFJO0lBQ1QsMkJBQVksQ0FBQyxLQUFLLEVBQUUsQ0FBQztBQUN6QixDQUFDOzs7Ozs7O0FDVEQsTUFBTSxLQUFLLEdBQVksS0FBSyxDQUFDO0FBRTdCLFNBQWdCLEdBQUcsQ0FBQyxHQUFXO0lBQzNCLElBQUksS0FBSyxFQUFFO1FBQ1AsV0FBVyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0tBQ3BCO1NBQU07UUFDSCxPQUFPLENBQUMsR0FBRyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0tBQ3BCO0FBQ0wsQ0FBQztBQU5ELGtCQU1DO0FBRUQsU0FBZ0IsV0FBVyxDQUFDLEdBQVc7SUFDbkMsSUFBSSxHQUFHLEdBQUcsa0JBQWtCLENBQUM7SUFDN0IsSUFBSSxPQUFPLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUM1QixPQUFPLENBQUMsQ0FBQyxDQUFDLFFBQVEsRUFBRSxHQUFHLENBQUMsQ0FBQztBQUM3QixDQUFDO0FBSkQsa0NBSUM7QUFDRCxTQUFpQixPQUFPLENBQUMsT0FBc0I7SUFDM0MsT0FBTyxDQUFDLEdBQUcsQ0FBQyxPQUFPLENBQUMsT0FBTyxFQUFFO1FBQ3pCLE1BQU0sRUFBRSxDQUFDO1FBQ1QsTUFBTSxFQUFFLEVBQUU7UUFDVixNQUFNLEVBQUUsSUFBSTtRQUNaLElBQUksRUFBRSxJQUFJO0tBQ2IsQ0FBQyxDQUFDLENBQUM7QUFDUixDQUFDO0FBUEQsMEJBT0M7QUFFRCxTQUFnQixRQUFRLENBQUMsT0FBZSxFQUFFLElBQVk7SUFDbEQsSUFBSSxLQUFLLEVBQUU7UUFDUCxXQUFXLENBQUMsT0FBTyxDQUFDLENBQUM7UUFDckIsT0FBTztLQUNWO0lBQ0QsSUFBSSxJQUFJLElBQUksU0FBUyxFQUFFO1FBQ25CLEdBQUcsQ0FBQyxPQUFPLENBQUMsQ0FBQTtRQUNaLE9BQU87S0FDVjtJQUNELFFBQVEsSUFBSSxFQUFFO1FBQ1YsS0FBSyxnQkFBUSxDQUFDLEtBQUs7WUFDZixHQUFHLENBQUMsT0FBTyxDQUFDLENBQUM7WUFDYixNQUFNO1FBQ1YsS0FBSyxnQkFBUSxDQUFDLEdBQUc7WUFDYixPQUFPLENBQUMsS0FBSyxDQUFDLE9BQU8sQ0FBQyxDQUFDO1lBQ3ZCLE1BQU07UUFDVixLQUFLLGdCQUFRLENBQUMsTUFBTTtZQUNoQixPQUFPLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxDQUFDO1lBQ3RCLE1BQU07UUFDVjtZQUNJLE9BQU8sQ0FBQyxHQUFHLENBQUMsT0FBTyxHQUFHLElBQUksR0FBRyxHQUFHLEdBQUcsT0FBTyxHQUFHLFNBQVMsQ0FBQyxDQUFDO1lBQ3hELE1BQU07S0FFYjtBQUVMLENBQUM7QUF6QkQsNEJBeUJDO0FBRVUsUUFBQSxRQUFRLEdBQUc7SUFDbEIsS0FBSyxFQUFFLENBQUM7SUFDUixHQUFHLEVBQUUsQ0FBQztJQUNOLE1BQU0sRUFBRSxDQUFDO0lBQ1QsR0FBRyxFQUFFLEVBQUU7SUFDUCxHQUFHLEVBQUUsRUFBRTtJQUNQLEdBQUcsRUFBRSxFQUFFO0lBQ1AsR0FBRyxFQUFFLEVBQUU7SUFDUCxHQUFHLEVBQUUsRUFBRTtJQUNQLEdBQUcsRUFBRSxFQUFFO0lBQ1AsR0FBRyxFQUFFLEVBQUU7SUFDUCxHQUFHLEVBQUUsRUFBRTtJQUNQLEdBQUcsRUFBRSxFQUFFO0lBQ1AsR0FBRyxFQUFFLEVBQUU7SUFDUCxHQUFHLEVBQUUsRUFBRTtJQUNQLEdBQUcsRUFBRSxFQUFFO0lBQ1AsR0FBRyxFQUFFLEVBQUU7SUFDUCxHQUFHLEVBQUUsRUFBRTtJQUNQLEdBQUcsRUFBRSxFQUFFO0lBQ1AsR0FBRyxFQUFFLEVBQUU7SUFDUCxHQUFHLEVBQUUsRUFBRTtJQUNQLEdBQUcsRUFBRSxFQUFFO0lBQ1AsR0FBRyxFQUFFLEVBQUU7SUFDUCxHQUFHLEVBQUUsRUFBRTtJQUNQLElBQUksRUFBRSxHQUFHO0lBQ1QsSUFBSSxFQUFFLEdBQUc7SUFDVCxJQUFJLEVBQUUsR0FBRztJQUNULElBQUksRUFBRSxHQUFHO0lBQ1QsSUFBSSxFQUFFLEdBQUc7SUFDVCxJQUFJLEVBQUUsR0FBRztJQUNULElBQUksRUFBRSxHQUFHO0lBQ1QsSUFBSSxFQUFFLEdBQUc7Q0FDWixDQUFBOzs7OztBQ25GRCxxQ0FBaUQ7QUFFakQsSUFBSSxVQUFVLENBQUM7QUFDZixJQUFJLFNBQVMsR0FBRyxJQUFJLENBQUM7QUFDckIsSUFBSSxRQUFRLENBQUM7QUFDYixJQUFJLE9BQU8sR0FBRyxJQUFJLEdBQUcsRUFBRSxDQUFDO0FBQ3hCLElBQUksWUFBWSxHQUFFLElBQUksR0FBRyxFQUFFLENBQUM7QUFFakIsUUFBQSxNQUFNLEdBQUc7SUFDaEIsS0FBSyxFQUFFLFVBQVUsTUFBTSxFQUFFLElBQUksRUFBRSxJQUFJO1FBQy9CLElBQUksTUFBTSxHQUFHLE9BQU8sQ0FBQyxnQkFBZ0IsQ0FBQyxNQUFNLENBQUMsQ0FBQztRQUM5QyxVQUFVLEdBQUcsTUFBTSxDQUFDLElBQUksQ0FBQztRQUN6QixJQUFBLFlBQUcsRUFBQyxJQUFJLENBQUMsU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLENBQUM7UUFFNUIsV0FBVyxDQUFDLE1BQU0sQ0FBQyxVQUFVLENBQUMsR0FBRyxDQUFDLElBQUksQ0FBQyxFQUFFO1lBQ3JDLE9BQU8sRUFBRSxVQUFVLElBQUk7Z0JBQ25CLElBQUksQ0FBQyxHQUFHLEdBQUcsT0FBTyxDQUFDLGtCQUFrQixFQUFFLENBQUM7Z0JBQ3hDLFNBQVM7Z0JBRVQsT0FBTyxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsR0FBRyxFQUFFO29CQUNyQixTQUFTLEVBQUUsVUFBVSxRQUFRO3dCQUN6QixJQUFJLFFBQVEsQ0FBQzt3QkFDYixNQUFNLFdBQVcsR0FBRyxRQUFRLENBQUMsSUFBSSxFQUFFLENBQUM7d0JBQ3BDLElBQUksWUFBWSxHQUFHLFdBQVcsQ0FBQyxPQUFPLENBQUM7d0JBQ3ZDLHNGQUFzRjt3QkFDdEYsSUFBSSxJQUFJLEtBQUssQ0FBQyxFQUFFOzRCQUNaLElBQUksR0FBRyxNQUFNLENBQUMsSUFBSSxDQUFDOzRCQUNuQixJQUFJLEdBQUMsQ0FBQyxDQUFDO3lCQUNWO3dCQUNELE1BQU0sWUFBWSxHQUFHLFlBQVksQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxJQUFJLENBQUM7NEJBQ2hFLFlBQVksQ0FBQyxPQUFPLENBQUMsVUFBVSxDQUFDLEdBQUcsQ0FBQyxJQUFJLENBQUMsQ0FBQyxHQUFHLENBQUMsSUFBSSxDQUFDLENBQUMsR0FBRyxDQUFDLENBQUM7d0JBQzdELEdBQUc7NEJBQ0MsSUFBSSxZQUFZLEVBQUU7Z0NBQ2QsSUFBSSxDQUFDLEdBQUcsY0FBYyxDQUFDLFdBQVcsQ0FBQyxDQUFDO2dDQUNwQyxJQUFJLE9BQU8sR0FBRyxXQUFXLENBQUMsT0FBTyxDQUFDO2dDQUNsQyxJQUFJLE1BQU0sR0FBRyxPQUFPLEdBQUcsVUFBVSxDQUFDO2dDQUNsQyxJQUFJLFFBQVEsR0FBRyxDQUFDLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxHQUFHLE1BQU0sR0FBRyxXQUFXLENBQUM7Z0NBQ3JELFlBQVksQ0FBQyxHQUFHLENBQUMsTUFBTSxFQUFDLElBQUksQ0FBQyxTQUFTLENBQUMsV0FBVyxDQUFDLENBQUMsQ0FBQztnQ0FDckQsT0FBTyxDQUFDLEdBQUcsQ0FBQyxNQUFNLEVBQUUsUUFBUSxDQUFDLENBQUM7Z0NBQzlCLFFBQVEsQ0FBQyxVQUFVLENBQUMsVUFBVSxPQUFPO29DQUNqQyxJQUFJLElBQUksR0FBRyxJQUFJLENBQUMsU0FBUyxDQUFDLE9BQU8sQ0FBQyxDQUFDO29DQUNuQyxJQUFJLFNBQVMsRUFBRTt3Q0FDWCxTQUFTLEdBQUcsS0FBSyxDQUFDO3dDQUNsQixPQUFPO3dDQUNQLFFBQVEsR0FBRyxlQUFlLENBQUMsT0FBTyxDQUFDLENBQUM7cUNBQ3ZDO3lDQUFNO3dDQUNILDZCQUE2Qjt3Q0FDN0IsSUFBSSxLQUFLLEdBQUcsUUFBUSxDQUFDLFFBQVEsQ0FBQyxDQUFDO3dDQUMvQixJQUFJLE1BQU0sR0FBRyxNQUFNLENBQUMsS0FBSyxDQUFDLEdBQUcsVUFBVSxDQUFDO3dDQUN4QyxJQUFJLE9BQU8sR0FBRyxPQUFPLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDO3dDQUNsQyxJQUFJLFNBQVMsR0FBRyxZQUFZLENBQUMsR0FBRyxDQUFDLE1BQU0sQ0FBQyxDQUFDO3dDQUN6Qyw4QkFBOEI7d0NBQzlCLElBQUksTUFBTSxHQUFHLFlBQVksQ0FBQyxPQUFPLEVBQUMsU0FBUyxDQUFDLENBQUM7d0NBQzdDLElBQUEsaUJBQVEsRUFBQyxPQUFPLEdBQUcsS0FBSyxHQUFHLE1BQU0sQ0FBQyxJQUFJLEVBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxDQUFDO3FDQUV4RDtnQ0FDTCxDQUFDLENBQUMsQ0FBQTs2QkFDTDs0QkFDRCxRQUFRLENBQUMsSUFBSSxFQUFFLENBQUE7eUJBRWxCLFFBQVEsUUFBUSxDQUFDLElBQUksRUFBRSxJQUFJLElBQUksRUFBQztvQkFDckMsQ0FBQztpQkFFSixDQUFDLENBQUE7WUFDTixDQUFDO1lBQ0QsT0FBTyxFQUFFLFVBQVUsR0FBRztnQkFDbEIsaUNBQWlDO2dCQUNqQyxPQUFPLENBQUMsUUFBUSxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFDM0IsSUFBQSxZQUFHLEVBQUMsTUFBTSxHQUFHLEdBQUcsQ0FBQyxDQUFDO1lBRXRCLENBQUM7U0FDSixDQUFDLENBQUE7SUFDTixDQUFDO0NBQ0osQ0FBQTtBQUVELFNBQVMsY0FBYyxDQUFDLEdBQUc7SUFDdkIsSUFBSSxDQUFDLEdBQUcsSUFBSSxDQUFDLFNBQVMsQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUM1QixJQUFJLE9BQU8sR0FBRyxHQUFHLENBQUMsT0FBTyxDQUFDO0lBQzFCLDBCQUEwQjtJQUMxQixJQUFJLE1BQU0sR0FBRyxPQUFPLEdBQUcsVUFBVSxDQUFDO0lBQ2xDLElBQUksRUFBRSxHQUFHLENBQUMsTUFBTSxDQUFDLENBQUMsUUFBUSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQy9CLElBQUksTUFBTSxHQUFHLEVBQUUsQ0FBQTtJQUNmLE1BQU0sQ0FBQyxPQUFPLEdBQUcsTUFBTSxDQUFDO0lBQ3hCLE9BQU8sRUFBRSxDQUFDO0FBQ2QsQ0FBQztBQUVELE1BQU0sU0FBUyxHQUFHLEVBQUUsQ0FBQztBQUVyQixLQUFLLElBQUksQ0FBQyxHQUFHLENBQUMsRUFBRSxDQUFDLElBQUksSUFBSSxFQUFFLEVBQUUsQ0FBQyxFQUFFO0lBQzVCLE1BQU0sUUFBUSxHQUFHLENBQUMsQ0FBQyxRQUFRLENBQUMsRUFBRSxDQUFDLENBQUMsUUFBUSxDQUFDLENBQUMsRUFBRSxHQUFHLENBQUMsQ0FBQztJQUNqRCxTQUFTLENBQUMsSUFBSSxDQUFDLFFBQVEsQ0FBQyxDQUFDO0NBQzVCO0FBRUQsU0FBUyxHQUFHLENBQUMsV0FBVztJQUNwQixNQUFNLElBQUksR0FBRyxJQUFJLFVBQVUsQ0FBQyxXQUFXLENBQUMsQ0FBQztJQUN6QyxNQUFNLFNBQVMsR0FBRyxFQUFFLENBQUM7SUFDckIsS0FBSyxJQUFJLENBQUMsR0FBRyxDQUFDLEVBQUUsQ0FBQyxHQUFHLElBQUksQ0FBQyxNQUFNLEVBQUUsRUFBRSxDQUFDO1FBQ2hDLFNBQVMsQ0FBQyxJQUFJLENBQUMsU0FBUyxDQUFDLElBQUksQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUM7SUFDdkMsT0FBTyxTQUFTLENBQUMsSUFBSSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBQzlCLENBQUM7QUFFRCxTQUFTLGVBQWUsQ0FBQyxPQUFPO0lBQzVCLElBQUksSUFBSSxHQUFHLEVBQUUsQ0FBQTtJQUNiLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEdBQUcsQ0FBQyxDQUFDO0lBQ3ZCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLElBQUksQ0FBQyxJQUFJLENBQUMsT0FBTyxDQUFDLEVBQUUsQ0FBQyxDQUFDO0lBQ3RCLE9BQU8sSUFBSSxDQUFDO0FBQ2hCLENBQUM7QUFFRCxTQUFTLFFBQVEsQ0FBQyxJQUFJO0lBQ2xCLE9BQU8sSUFBSSxDQUFDLEVBQUUsQ0FBQyxDQUFDO0FBQ3BCLENBQUM7QUFFRCxTQUFTLFlBQVksQ0FB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Q0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBOzs7QUN4TEE7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0EiLCJmaWxlIjoiZ2VuZXJhdGVkLmpzIiwic291cmNlUm9vdCI6IiJ9

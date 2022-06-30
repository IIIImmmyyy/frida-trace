(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
(function (setImmediate){(function (){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const straceInject_1 = require("./straceInject");
setImmediate(main);
function main() {
    straceInject_1.straceInject.start();
    // log("hookStart");
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
let soName = "libtprt.so";
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
    strace_1.strace.start(soName, 0x32960, 0x1478);
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
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbIm5vZGVfbW9kdWxlcy9icm93c2VyLXBhY2svX3ByZWx1ZGUuanMiLCJhZ2VudC9pbmRleC50cyIsImFnZW50L2xvZ2dlci50cyIsImFnZW50L3N0cmFjZS5qcyIsImFnZW50L3N0cmFjZUluamVjdC5qcyIsIm5vZGVfbW9kdWxlcy9wcm9jZXNzL2Jyb3dzZXIuanMiLCJub2RlX21vZHVsZXMvdGltZXJzLWJyb3dzZXJpZnkvbWFpbi5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiQUFBQTs7OztBQ0VBLGlEQUE0QztBQUc1QyxZQUFZLENBQUMsSUFBSSxDQUFDLENBQUE7QUFFbEIsU0FBUyxJQUFJO0lBQ1QsMkJBQVksQ0FBQyxLQUFLLEVBQUUsQ0FBQztJQUNyQixvQkFBb0I7QUFFeEIsQ0FBQzs7Ozs7OztBQ1hELE1BQU0sS0FBSyxHQUFZLEtBQUssQ0FBQztBQUU3QixTQUFnQixHQUFHLENBQUMsR0FBVztJQUMzQixJQUFJLEtBQUssRUFBRTtRQUNQLFdBQVcsQ0FBQyxHQUFHLENBQUMsQ0FBQztLQUNwQjtTQUFNO1FBQ0gsT0FBTyxDQUFDLEdBQUcsQ0FBQyxHQUFHLENBQUMsQ0FBQztLQUNwQjtBQUNMLENBQUM7QUFORCxrQkFNQztBQUVELFNBQWdCLFdBQVcsQ0FBQyxHQUFXO0lBQ25DLElBQUksR0FBRyxHQUFHLGtCQUFrQixDQUFDO0lBQzdCLElBQUksT0FBTyxHQUFHLElBQUksQ0FBQyxHQUFHLENBQUMsR0FBRyxDQUFDLENBQUM7SUFDNUIsT0FBTyxDQUFDLENBQUMsQ0FBQyxRQUFRLEVBQUUsR0FBRyxDQUFDLENBQUM7QUFDN0IsQ0FBQztBQUpELGtDQUlDO0FBQ0QsU0FBaUIsT0FBTyxDQUFDLE9BQXNCO0lBQzNDLE9BQU8sQ0FBQyxHQUFHLENBQUMsT0FBTyxDQUFDLE9BQU8sRUFBRTtRQUN6QixNQUFNLEVBQUUsQ0FBQztRQUNULE1BQU0sRUFBRSxFQUFFO1FBQ1YsTUFBTSxFQUFFLElBQUk7UUFDWixJQUFJLEVBQUUsSUFBSTtLQUNi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QUFFLENBQUE7SUFDYixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUN2QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixJQUFJLENBQUMsSUFBSSxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQztJQUN0QixPQUFPLElBQUksQ0FBQztBQUNoQixDQUFDO0FBRUQsU0FBUyxRQUFRLENBQUMsSUFBSTtJQUNsQixPQUFPLElBQUksQ0FBQyxFQUFFLENBQUMsQ0FBQztBQUNwQixDQUFDO0FBRUQs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O0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTs7O0FDeExBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBO0FBQ0E7QUFDQTtBQUNBIiwiZmlsZSI6ImdlbmVyYXRlZC5qcyIsInNvdXJjZVJvb3QiOiIifQ==

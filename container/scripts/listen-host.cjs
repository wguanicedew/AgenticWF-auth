// Preloaded into Logto (node --require) when LISTEN_HOST is set.
//
// Logto calls server.listen(port) without a host, i.e. it binds every interface. With
// `docker run --network host` that would expose :3001/:3002 on the host's public
// interfaces, so this injects LISTEN_HOST (e.g. 127.0.0.1) into port-only listen calls.
'use strict';

const net = require('node:net');

const host = process.env.LISTEN_HOST;
const originalListen = net.Server.prototype.listen;

net.Server.prototype.listen = function listen(...args) {
  const [first, second] = args;
  if (typeof first === 'number' || (typeof first === 'string' && /^\d+$/.test(first))) {
    if (typeof second !== 'string') {
      args.splice(1, 0, host); // listen(port[, backlog][, cb]) -> listen(port, host, ...)
    }
  } else if (first && typeof first === 'object' && first.port !== undefined && !first.host && !first.path) {
    args[0] = { ...first, host };
  }
  return originalListen.apply(this, args);
};

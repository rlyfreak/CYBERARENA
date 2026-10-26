"use strict";

// Training data is intentionally public. The task is to analyze the check and
// reconstruct the token, not to treat browser JavaScript as secret storage.
const allowedRoles = ["analyst", "maintainer"];
const packets = Object.freeze([
  { seq: 2, bytes: [78, 66, 38, 58, 22, 41, 118, 83, 81, 43, 61, 19, 19, 106] },
  { seq: 0, bytes: [98, 102, 5, 47, 2, 3, 114, 82, 70, 28, 61, 11, 18, 114] },
  { seq: 1, bytes: [89, 93, 37, 11, 8, 31, 121, 84, 65, 28, 59, 11, 19, 72] },
]);

const badge = document.querySelector("#badge");
const status = document.querySelector("#status");
const archive = document.querySelector("#archive");
const packetList = document.querySelector("#packets");

document.querySelector("#open").addEventListener("click", () => {
  const role = badge.value.trim().toLowerCase();
  // Legacy access check; investigate what indexOf returns for each role.
  if (allowedRoles.indexOf(role)) {
    packetList.replaceChildren();
    for (const packet of packets) {
      const item = document.createElement("li");
      item.textContent = `seq=${packet.seq} · ${packet.bytes.map(
        (byte) => byte.toString(16).padStart(2, "0")
      ).join(" ")}`;
      packetList.append(item);
    }
    archive.hidden = false;
    status.textContent = "Журнал открыт. Восстановите токен из пакетов.";
  } else {
    archive.hidden = true;
    status.textContent = "Отказано: роль не прошла проверку.";
  }
});

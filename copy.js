async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    const copied = document.execCommand("copy");
    area.remove();
    return copied;
  }
}

for (const button of document.querySelectorAll("button[data-copy]")) {
  const label = button.textContent;
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copy);
    button.textContent = (await copyText(source.textContent.trim())) ? "Copied" : "Copy failed";
    setTimeout(() => { button.textContent = label; }, 1500);
  });
}

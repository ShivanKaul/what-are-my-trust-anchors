for (const button of document.querySelectorAll("button[data-copy]")) {
  const label = button.textContent;
  button.addEventListener("click", async () => {
    const source = document.getElementById(button.dataset.copy);
    try {
      await navigator.clipboard.writeText(source.textContent.trim());
      button.textContent = "Copied";
    } catch {
      button.textContent = "Copy failed";
    }
    setTimeout(() => { button.textContent = label; }, 1500);
  });
}

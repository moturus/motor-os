// Share the navigation markup while keeping each page's existing sidebar styles.
(async () => {
  const sidebar = document.querySelector('.sidebar');
  if (!sidebar) return;

  try {
    const response = await fetch('sidebar.html');
    if (!response.ok) throw new Error(`Sidebar request failed: ${response.status}`);

    const template = document.createElement('template');
    template.innerHTML = await response.text();
    const nav = template.content.querySelector('nav[aria-label="Documentation"]');
    if (!nav) throw new Error('Sidebar navigation is missing');

    for (const link of nav.querySelectorAll('a[href]')) {
      if (new URL(link.getAttribute('href'), document.baseURI).pathname === location.pathname) {
        link.classList.add('current');
        link.setAttribute('aria-current', 'page');
      }
    }
    sidebar.replaceChildren(nav);
  } catch (error) {
    // Leave the Documentation link usable when the fragment cannot be loaded.
    console.warn('Unable to load the documentation sidebar:', error);
  }
})();

document.querySelectorAll('.docs-sidebar a').forEach(link => {
  link.addEventListener('click', e => {
    e.preventDefault();
    const targetId = link.getAttribute('href').substring(1);
    const collapseEl = document.getElementById(targetId); // ✅ updated

    console.log(collapseEl); // should now log the accordion div

    if (collapseEl) {
      const bsCollapse = new bootstrap.Collapse(collapseEl, { toggle: true });
      collapseEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    document.querySelectorAll('.docs-sidebar a').forEach(a => a.classList.remove('active'));
    link.classList.add('active');
  });
});



document.querySelectorAll('.copy-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    const code = btn.nextElementSibling.innerText;
    navigator.clipboard.writeText(code).then(() => {
      btn.style.opacity = '0.3';      // make icon transparent
      
      setTimeout(() => {
        btn.textContent = '📋';       // restore icon
        btn.style.opacity = '1';      // restore opacity
      }, 500);
    });
  });
});

// Select all sidebar links
const sidebarLinks = document.querySelectorAll('.docs-sidebar a');

// Listen for each accordion item
const accordionItems = document.querySelectorAll('.accordion-collapse');

accordionItems.forEach(item => {
    item.addEventListener('show.bs.collapse', () => {
        // Remove active from all links
        sidebarLinks.forEach(link => link.classList.remove('active'));

        // Get the ID of the opening accordion
        const id = item.id; // e.g., "collapseRequirements"

        // Find matching sidebar link
        const link = document.querySelector(`.docs-sidebar a[href="#${id.replace('collapse', '').toLowerCase()}"]`);
        if (link) link.classList.add('active');
    });
});

document.addEventListener('DOMContentLoaded', () => {
    const toggleBtn = document.querySelector('.docs-toggle-btn');
    const sidebar = document.querySelector('.docs-sidebar');

    toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('show');
    });
});
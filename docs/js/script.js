window.addEventListener("scroll", () => {
  const navbar = document.querySelector(".navbar");
  if (window.scrollY > 50) {
    navbar.classList.add("scrolled");
  } else {
    navbar.classList.remove("scrolled");
  }
});

const canvas = document.getElementById('heroCanvas');
const ctx = canvas.getContext('2d');

let particlesArray;
const numberOfParticles = 80;
const maxDistance = 120;
const mouse = { x: null, y: null };
canvas.addEventListener('mousemove', (e) => {
  const rect = canvas.getBoundingClientRect();
  mouse.x = e.clientX - rect.left;
  mouse.y = e.clientY - rect.top;
});

canvas.addEventListener('mouseleave', () => {
  mouse.x = null;
  mouse.y = null;
});

canvas.width = window.innerWidth;
canvas.height = window.innerHeight;

window.addEventListener('resize', () => {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  initParticles();
});

class Particle {
  constructor() {
    this.x = Math.random() * canvas.width;
    this.y = Math.random() * canvas.height;
    this.size = Math.random() * 2 + 1;
    this.speedX = (Math.random() - 0.5) * 0.5;
    this.speedY = (Math.random() - 0.5) * 0.5;
  }

  update() {
    this.x += this.speedX;
    this.y += this.speedY;

    if (this.x > canvas.width || this.x < 0) this.speedX *= -1;
    if (this.y > canvas.height || this.y < 0) this.speedY *= -1;

    if (mouse.x !== null && mouse.y !== null) {
      const dx = mouse.x - this.x;
      const dy = mouse.y - this.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 100) {
        this.x += dx * 0.01;
        this.y += dy * 0.01;
      }
    }
  }

  draw() {
    ctx.fillStyle = '#a855f7';
    ctx.beginPath();
    ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
    ctx.fill();
  }
}

function initParticles() {
  particlesArray = [];
  for (let i = 0; i < numberOfParticles; i++) {
    particlesArray.push(new Particle());
  }
}

function connectParticles() {
  for (let a = 0; a < particlesArray.length; a++) {
    for (let b = a + 1; b < particlesArray.length; b++) {
      const dx = particlesArray[a].x - particlesArray[b].x;
      const dy = particlesArray[a].y - particlesArray[b].y;
      const distance = Math.sqrt(dx * dx + dy * dy);
      if (distance < maxDistance) {
        ctx.strokeStyle = `rgba(168,85,247,${1 - distance / maxDistance})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(particlesArray[a].x, particlesArray[a].y);
        ctx.lineTo(particlesArray[b].x, particlesArray[b].y);
        ctx.stroke();
      }
    }
  }
}

function animate() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  particlesArray.forEach(p => {
    p.update();
    p.draw();
  });
  connectParticles();
  requestAnimationFrame(animate);
}

initParticles();
animate();

document.addEventListener("DOMContentLoaded", () => {
  const filterBtns = document.querySelectorAll(".filter-btn");
  const galleryItems = document.querySelectorAll(".gallery-item");

  filterBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      filterBtns.forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      const filter = btn.dataset.filter;

      galleryItems.forEach(item => {
        if (filter === "all" || item.classList.contains(filter)) {
          item.style.display = "block";
          requestAnimationFrame(() => {
            item.classList.remove("hidden");
          });
        } else {
          item.classList.add("hidden");
          setTimeout(() => {
            if (item.classList.contains("hidden")) {
              item.style.display = "none";
            }
          }, 300); 
        }
      });
    });
  });

  const lightbox = document.getElementById("lightbox");
  const lightboxImg = document.querySelector(".lightbox-img");
  const lightboxClose = document.querySelector(".lightbox-close");

  document.querySelectorAll(".gallery-item").forEach(item => {
    const img = item.querySelector("img");

    if (img) {
      img.addEventListener("click", (e) => {
        e.stopPropagation(); 
        lightboxImg.src = img.src;
        lightbox.style.display = "flex";
      });
    }
  });

  lightboxClose.addEventListener("click", (e) => {
    e.stopPropagation(); 
    lightbox.style.display = "none";
  });

  lightbox.addEventListener("click", (e) => {
    if (e.target === lightbox) {
      lightbox.style.display = "none";
    }
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (lightbox.style.display === "flex") lightbox.style.display = "none";
    }
  });

});

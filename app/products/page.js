"use client";
import { useState, useEffect } from 'react';

export default function ProductsPage() {
  const [perfumes, setPerfumes] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch('/api/perfumes')
      .then((res) => res.json())
      .then((data) => {
        setPerfumes(data);
        setLoading(false);
      });
  }, []);

  const handleWhatsAppOrder = (name, price) => {
    const phone = "234XXXXXXXXXX"; // Put your WhatsApp number here
    const message = `Hello! I am interested in ordering the ${name} perfume priced at $${price}.`;
    window.open(`https://wa.me/${phone}?text=${encodeURIComponent(message)}`, '_blank');
  };

  return (
    <div className="min-h-screen bg-white text-black font-serif">
      {/* 1. Sticky Navbar */}
      <nav className="p-4 md:p-6 border-b border-gray-50 flex justify-between items-center bg-white/80 backdrop-blur-md sticky top-0 z-50">
        <img src="/logo.png" alt="themotundebrand logo" className="h-10 md:h-14 w-auto" />
        <div className="hidden md:flex gap-10 text-xs uppercase tracking-[0.2em] font-sans">
          <span className="cursor-pointer hover:text-brand-pink transition">Collection</span>
          <span className="cursor-pointer hover:text-brand-pink transition">Our Story</span>
          <span className="cursor-pointer hover:text-brand-pink transition">Contact</span>
        </div>
        {/* Mobile Menu Icon (Placeholder) */}
        <div className="md:hidden text-2xl">☰</div>
      </nav>

      {/* 2. Hero Header - Luxury Styling */}
      <header className="py-16 md:py-24 text-center px-4 bg-[#fffafb]">
        <h1 className="text-3xl md:text-5xl mb-4 uppercase tracking-[0.3em] font-light">
          The Collection
        </h1>
        <div className="w-20 h-[1px] bg-brand-pink mx-auto mb-6"></div>
        <p className="text-gray-500 italic text-sm md:text-base max-w-md mx-auto">
          Discover your signature scent from our curated range of luxury fragrances.
        </p>
      </header>

      {/* 3. Responsive Product Grid */}
      <main className="max-w-7xl mx-auto px-6 py-12">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-20">
             <div className="w-8 h-8 border-4 border-brand-pink border-t-transparent rounded-full animate-spin mb-4"></div>
             <p className="tracking-widest text-xs uppercase">Curating Scents...</p>
          </div>
        ) : (
          /* Grid: 1 column on mobile, 2 on small tablets, 3 on desktop */
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-8 gap-y-16">
            {perfumes.map((perfume) => (
              <div key={perfume._id} className="group">
                {/* Image Container */}
                <div className="relative overflow-hidden bg-[#f9f9f9] aspect-[3/4] rounded-sm shadow-sm transition-all duration-500 group-hover:shadow-xl">
                  <img 
                    src={perfume.image} 
                    alt={perfume.name}
                    className="object-cover w-full h-full transition-transform duration-1000 group-hover:scale-110"
                  />
                  
                  {/* Overlay Button - Hidden on mobile, shows on hover for desktop */}
                  <div className="absolute inset-0 bg-black/5 opacity-0 group-hover:opacity-100 transition-opacity flex items-end p-6">
                    <button 
                      onClick={() => handleWhatsAppOrder(perfume.name, perfume.price)}
                      className="w-full bg-white text-black py-4 text-xs uppercase tracking-widest font-sans hover:bg-black hover:text-white transition-colors duration-300"
                    >
                      Order via WhatsApp
                    </button>
                  </div>
                </div>

                {/* Product Info */}
                <div className="mt-6 text-center">
                  <h3 className="text-lg md:text-xl font-light uppercase tracking-wider mb-2">
                    {perfume.name}
                  </h3>
                  <p className="text-brand-pink font-sans font-medium text-sm">
                    ${perfume.price}
                  </p>
                  
                  {/* Order Button for Mobile (always visible) */}
                  <button 
                    onClick={() => handleWhatsAppOrder(perfume.name, perfume.price)}
                    className="mt-4 md:hidden w-full border border-black py-3 text-[10px] uppercase tracking-widest"
                  >
                    Order Now
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </main>

      {/* 4. Simple Footer */}
      <footer className="bg-white border-t border-gray-100 py-12 mt-20 text-center">
        <p className="text-[10px] uppercase tracking-[0.3em] text-gray-400">
          © 2025 THEMOTUNDEBRAND. All Rights Reserved.
        </p>
      </footer>
    </div>
  );
}
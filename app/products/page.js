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

  return (
    <div className="min-h-screen bg-white text-black">
      {/* Navbar with Logo */}
      <nav className="p-4 border-b border-gray-100 flex justify-between items-center bg-white sticky top-0 z-50">
        <img src="https://i.imgur.com/CVKXV7R.png" alt="logo" className="h-12" />
        <div className="flex gap-6 font-medium">
          <span className="cursor-pointer hover:text-pink-400">Shop</span>
          <span className="cursor-pointer hover:text-pink-400">Our Story</span>
        </div>
      </nav>

      {/* Hero Header */}
      <header className="py-12 text-center bg-pink-50">
        <h1 className="text-4xl font-serif mb-2 uppercase tracking-widest">The Collection</h1>
        <p className="text-gray-600">Luxury scents by themotundebrand</p>
      </header>

      {/* Product Grid */}
      <main className="max-w-7xl mx-auto p-8">
        {loading ? (
          <div className="text-center py-20">Finding the perfect scent...</div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-10">
            {perfumes.map((perfume) => (
              <div key={perfume._id} className="group cursor-pointer">
                <div className="relative overflow-hidden rounded-lg bg-gray-100 aspect-[4/5]">
                  <img 
                    src={perfume.image} 
                    alt={perfume.name}
                    className="object-cover w-full h-full transition transform group-hover:scale-105"
                  />
                  <button className="absolute bottom-4 left-1/2 -translate-x-1/2 bg-black text-white px-6 py-2 opacity-0 group-hover:opacity-100 transition duration-300 rounded-full hover:bg-pink-500">
                    Add to Cart
                  </button>
                </div>
                <h3 className="mt-4 text-xl font-semibold">{perfume.name}</h3>
                <p className="text-pink-500 font-bold">${perfume.price}</p>
              </div>
            ))}
          </div>
        )}
      </main>
    </div>
  );
}
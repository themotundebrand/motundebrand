"use client";
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function SplashScreen() {
  const router = useRouter();
  const [currentImg, setCurrentImg] = useState(0);

  const images = [
    "https://i.imgur.com/KQ2leiY.jpeg",
    "https://i.imgur.com/Wp0HCu8.jpeg",
    "https://i.imgur.com/BRl8AVs.jpeg"
  ];

  useEffect(() => {
    // Cycles images every 1.3 seconds
    const imageInterval = setInterval(() => {
      setCurrentImg((prev) => (prev + 1) % images.length);
    }, 1300);

    // Redirects to products after 5 seconds (allows users to see the sequence)
    const redirectTimer = setTimeout(() => {
      router.push('/products');
    }, 5000);

    return () => {
      clearInterval(imageInterval);
      clearTimeout(redirectTimer);
    };
  }, [router, images.length]);

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-white px-4">
      
      {/* 1. Logo Section - Responsive scaling */}
      <div className="mb-8 md:mb-12 animate-pulse">
        <img 
          src="/logo.png" 
          alt="themotundebrand logo" 
          className="h-16 md:h-24 w-auto object-contain"
        />
      </div>

      {/* 2. Responsive Image Container */}
      {/* Mobile: Width is 90% of screen. Desktop: Fixed max-width and taller height */}
      <div className="relative w-[90%] md:w-full md:max-w-lg aspect-[3/4] overflow-hidden rounded-2xl shadow-2xl border-4 border-brand-pink">
        {images.map((img, index) => (
          <img
            key={index}
            src={img}
            alt={`Luxury Perfume ${index + 1}`}
            className={`absolute inset-0 w-full h-full object-cover transition-all duration-1000 ease-in-out ${
              index === currentImg 
                ? "opacity-100 scale-100 translate-x-0" 
                : "opacity-0 scale-105 translate-x-4"
            }`}
          />
        ))}
      </div>

      {/* 3. Responsive Loading Text */}
      <div className="mt-10 text-center">
        <p className="text-brand-black font-serif text-sm md:text-lg tracking-[0.3em] uppercase animate-bounce">
          Entering themotundebrand
        </p>
        <div className="mt-2 flex justify-center gap-2">
          {images.map((_, i) => (
            <div 
              key={i}
              className={`h-1 transition-all duration-500 rounded-full ${
                i === currentImg ? "w-8 bg-brand-pink" : "w-2 bg-gray-200"
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
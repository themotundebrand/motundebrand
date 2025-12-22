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
    // Switch images every 1.2 seconds to show all 3 within ~4 seconds
    const imageInterval = setInterval(() => {
      setCurrentImg((prev) => (prev + 1) % images.length);
    }, 1200);

    const redirectTimer = setTimeout(() => {
      router.push('/products');
    }, 4500);

    return () => {
      clearInterval(imageInterval);
      clearTimeout(redirectTimer);
    };
  }, [router, images.length]);

  return (
    <div className="fixed inset-0 flex flex-col items-center justify-center bg-white z-50 px-6">
      
      {/* 1. Logo Section - Scaled for Mobile/Desktop */}
      <div className="mb-10 md:mb-14 animate-pulse">
        <img 
          src="/logo.png" 
          alt="themotundebrand logo" 
          className="h-20 md:h-32 w-auto object-contain"
        />
      </div>

      {/* 2. Optimized Image Container */}
      {/* We use 'relative' here and 'absolute' on images so they stack! */}
      <div className="relative w-full max-w-[320px] md:max-w-[400px] aspect-[3/4] overflow-hidden rounded-3xl shadow-[0_20px_50px_rgba(255,192,203,0.3)] border-[6px] border-brand-pink bg-gray-50">
        {images.map((img, index) => (
          <img
            key={index}
            src={img}
            alt="Luxury Perfume"
            className={`absolute inset-0 w-full h-full object-cover transition-opacity duration-1000 ease-in-out ${
              index === currentImg ? "opacity-100 scale-100" : "opacity-0 scale-110"
            }`}
          />
        ))}
      </div>

      {/* 3. Luxury Loading Text & Indicators */}
      <div className="mt-12 text-center">
        <p className="text-brand-black font-serif text-sm md:text-base tracking-[0.4em] uppercase opacity-80 mb-4">
          The Motunde Brand
        </p>
        
        {/* Visual Progress Dots */}
        <div className="flex justify-center gap-3">
          {images.map((_, i) => (
            <div 
              key={i}
              className={`h-1.5 transition-all duration-500 rounded-full ${
                i === currentImg ? "w-10 bg-brand-pink" : "w-3 bg-gray-200"
              }`}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
"use client";
import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Image from 'next/image';

export default function SplashScreen() {
  const router = useRouter();
  const [currentImg, setCurrentImg] = useState(0);

  const images = [
    "https://i.imgur.com/KQ2leiY.jpeg",
    "https://i.imgur.com/Wp0HCu8.jpeg",
    "https://i.imgur.com/BRl8AVs.jpeg"
  ];

  useEffect(() => {
    // Rotate images every 1.2 seconds
    const imageInterval = setInterval(() => {
      setCurrentImg((prev) => (prev + 1) % images.length);
    }, 1200);

    // Redirect to products after 4 seconds
    const redirectTimer = setTimeout(() => {
      router.push('/products');
    }, 4000);

    return () => {
      clearInterval(imageInterval);
      clearTimeout(redirectTimer);
    };
  }, [router, images.length]);

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-white">
      {/* Logo Area */}
      <div className="mb-10 animate-fade-in">
        <img 
          src="https://i.imgur.com/CVKXV7R.png" 
          alt="themotundebrand logo" 
          className="h-24 w-auto object-contain"
        />
      </div>

      {/* Image Display Area */}
      <div className="relative w-full max-w-md h-96 overflow-hidden rounded-lg shadow-2xl border-4 border-brand-pink">
        {images.map((img, index) => (
          <img
            key={index}
            src={img}
            alt={`Perfume display ${index}`}
            className={`absolute inset-0 w-full h-full object-cover transition-opacity duration-700 ease-in-out ${
              index === currentImg ? "opacity-100" : "opacity-0"
            }`}
          />
        ))}
      </div>

      {/* Loading Text */}
      <p className="mt-8 text-brand-black font-serif tracking-widest animate-pulse">
        ENTERING THEMOTUNDEBRAND...
      </p>
    </div>
  );
}
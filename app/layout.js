import './globals.css'

export const metadata = {
  title: 'themotundebrand | Luxury Perfumes',
  description: 'Exquisite scents for the modern individual',
}

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body className="bg-white text-black antialiased">
        {children}
      </body>
    </html>
  )
}
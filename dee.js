import Features from '@/components/features/page'
import Footer from '@/components/footer/page'
import Header from '@/components/header/page'
import Howitworks from '@/components/howitworks/page'
import Testimonial from '@/components/testimonial/page'
import Link from 'next/link'
import Image from 'next/image'

export default function Home() {
  return (

    <main className="flex min-h-screen h-auto bg-white flex-col items-center w-screen box-border ">
      <Header />
      <div className='backgroundscreen w-screen min-h-screen flex flex-col items-center justify-center sm:flex-row pt-12' style={{
        backgroundImage: "url('../globackground.jpg')",
        backgroundSize: 'cover',
        backgroundRepeat: 'no-repeat',
      }}>
        <div className='textbox w-11/12 h-auto sm:w-11/12'>
          <p className='text-white shadow-yellow-500 text-6xl sm:text-7xl font-interbold text-center -mt-36'>Explore Virtual Halls</p>
          <p className='text-center font-inter sm:font-interbold font-bold text-xl sm:text-2xl text-slate-800 p-2 sm:p-5'>Welcome to Opine ,Where Conversations come to life in virtual halls , Join Interactive sessions and engage with hosts like never before. </p>
          <div className='flex flex-col items-center'>
          <div className="flex items-center flex-row w-auto">
            <Link href="/login"><button className="text-black text-md font-semibold px-3 py-1 w-auto h-auto rounded-md bg-white border-amber-500 border shadow-md mx-3 font-intermedium">Login</button></Link>
            <Link href="/signup"><button className="text-white mx-3 bg-amber-500 sm:px-5 px-3 py-1  hover:animate-none shadow-md shadow-black rounded-md text-sm font-intermedium">Get Started</button></Link>
          </div>
        </div>
        </div>
        
      </div>
      <Features />
      <Howitworks />
      <Testimonial />
      <div className='w-screen h-auto flex flex-col sm:flex-row my-8 justify-around items-center'>
        <div>
          <p className=' text-center text-2xl text-slate-700 mb-12 font-medium'>Join Opine today!  </p>
          <div className='w-full h-auto p-2 flex justify-center items-center'>
            <a href='/login'><button className='w-32 h-10 rounded-sm bg-navy text-white shadow-slate-700 font-bold font-intermedium border-2 border-white mx-3 mb-4 flex items-center justify-around'>Login</button></a>
            <a href='/signup'><button className='w-32 h-10 rounded-sm shadow-sm shadow-mycolor  bg-white font-bold font-intermedium border-2 border-navy mx-3  text-black mb-4 flex items-center justify-around'>Register</button></a>
          </div>

        </div>

        <div className=''>
          <img
            src="/girl.png"
            alt="My Image"
            width={200}
            height={200}

          />
        </div>
      </div>
      <Footer />
    </main>
  )
}

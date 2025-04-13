import AboutSectionOne from "components/About/AboutSectionOne";
import Blog from "components/Blog";
// import Brands from "components/Brands";
import ScrollUp from "components/Common/ScrollUp";
import Contact from "components/Contact";
import Features from "components/Features";
import Hero from "components/Hero";
import Pricing from "components/Pricing";
// import Testimonials from "components/Testimonials";
import Video from "components/Video";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Healthcare.gov",
  description: "HealthCare.gov is your trusted source for Affordable Care Act (ACA) health plans. Explore coverage options, apply for financial assistance, and enroll in quality health insurance today.",
  // other metadata
};

export default function Home() {
  return (
    <>
      <ScrollUp />
      {/* <Hero /> */}
      <Video />
      <Features />
      {/* <Brands /> */}
      {/* <AboutSectionOne />
      <AboutSectionTwo /> */}
      {/* <Testimonials /> */}
      {/* <Pricing /> */}
      {/* <Blog />
      <Contact /> */}
    </>
  );
}

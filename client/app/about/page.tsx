import AboutSectionOne from "components/About/AboutSectionOne";
import Breadcrumb from "components/Common/Breadcrumb";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: "About Page | Healthcare.gov",
  description: "Learn more about our mission to simplify access to affordable health insurance. Discover how we help individuals and families compare ACA health plans and enroll with confidence.",
  // other metadata
};

const AboutPage = () => {
  return (
    <>
      <Breadcrumb
        pageName="About Page"
        description="Learn more about our mission to simplify access to affordable health insurance. Discover how we help individuals and families compare ACA health plans and enroll with confidence."
      />
      <AboutSectionOne />
    </>
  );
};

export default AboutPage;

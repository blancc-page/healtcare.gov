import Breadcrumb from "@/client/components/Common/Breadcrumb";
import Contact from "@/client/components/Contact";

import { Metadata } from "next";

export const metadata: Metadata = {
  title: "Contact Page | Healthcare.gov",
  description: "Need help with your health insurance application or plan? Visit our Support Center for answers to common questions, step-by-step guides, and live assistance.",
  // other metadata
};

const ContactPage = () => {
  return (
    <>
      <Breadcrumb
        pageName="Contact Page"
        description="Need help with your health insurance application or plan? Visit our Support Center for answers to common questions, step-by-step guides, and live assistance."
      />

      <Contact />
    </>
  );
};

export default ContactPage;

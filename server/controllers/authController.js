import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/usermodel.js';
import transporter from '../config/nomdemailer.js';


export const register = async(req,res) =>{
    const {name, email, password, idNum} = req.body;

    if(!idNum || !name || !email || !password){
        return res.json({success: false, message: 'User Not Created!'})
    }

    try{
        const existingUser = await userModel.findOne({email})
        if(existingUser){
            return res.json({success: false, message: 'User Already Created!'})
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({idNum, name, email, password: hashedPassword});

        await user.save();

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '7d'}); // OTP lifespan supposed to be shorter 

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production',
            sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
    });

//sending welcome e-mail
    const mailOption = {
        from: process.env.SENDER_EMAIL,
        to: email,
        subject: 'Welcome to Heathcare.gov',
        text: `Hi ${name}, welcome to healthcare.gov.
        
        Your account is under the email: '${email}' and ID Number: '${idNum}'. Use these to login in.`
    }
    console.log(`${name} and ${email} and ${idNum} and ${process.env.SENDER_EMAIL}`);
    await transporter.sendMail(mailOption);
    console.log("mail sent");

    return res.json({success:true});

    } catch(error){
        res.json({success: false, message: error.message})
    }
}

export const login = async(req,res) => {
    const {idNum, email, password} = req.body;// check this

    if(!idNum && !password|| !email && !password){
        return res.json({success: false, message: "Email / ID and Password Are Required!"})
    }

    try {
        const user = await userModel.findOne({$or: [{ idNum }, { email }]}); // check this

        if(!user){
            return res.json({success:false, message: 'Invalid Email / ID'})
        }

        const isMatch = await bcrypt.compare(password, user.password);


        if (!isMatch) {
            return res.json({success:false, message: 'Invalid password'})
        }

        const token = jwt.sign({id: user._id}, process.env.JWT_SECRET, {expiresIn: '1h'}); // OTP lifespan supposed to be shorter 

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production',
            sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
    });

    return res.json({success:true});


    } catch (error) {
        return res.json({success: false, message: error.message});
    }
} 


export const logout = async (req,res) => {
    try {
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV == 'production',
            sameSite: process.env.NODE_ENV == 'production' ? 'none' : 'strict'
        })

        return res.json({success: true, message: "User Logged Out"})
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

//Send Verification OTP to User's Email
export const sendVerifyOtp = async (req, res) => {
    try {
        const {userId} = req.body;
        const user = await userModel.findById(userId);

        if(user.isAccountVerified){
            return res.json({success: false, message: "Account already Verified"})
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 60000 * 60// otp expiry 1min
        
        await user.save();

        const mailOption = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            text: `Hi ${user.name}, your OTP is ${otp}.
            Veify your account using this OTP.`
        }

        await transporter.sendMail(mailOption);

        res.json({success: true, message: 'Verification OTP sent on Email'});

    } catch (error) {
        return res.json({success: false, message: 'error.message'});
    }
}

export const verifyEmail = async(req,res) => {

    const {userId,otp} = req.body;

    if(!userId || !otp){
        return res.json({success: false, message: 'Missing Details'});
    }

    try {
        const user = await userModel.findById(userId);

        if(!user){
            return res.json({success: false, message: 'User is not Found'});
        }

        if(user.verifyOtp === '' || user.verifyOtp !== otp){
            return res.json({success: false, message: 'Invalid OTP'});
        }

        if(user.verifyOtpExpireAt < Date.now()){
            return res.json({success: false, message: 'OTP Expired'});
        }

        user.isAccountVerified = true;
        user.verifyOTP = '';
        user.verifyOtpExpireAt = 0;

        await user.save();
        return res.json({success: true, message: 'Email Verified successfully'});

    } catch (error) {
        return res.json({success: false, message: error.message});
    }

}

export const isAuthenticated = async(req,res) => {
    try {
        return res.json({success: true});
    } catch (error) {
        return res.json({success: false, message: error.message});
    }
}

export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    // Validate email with proper status code
    if (!email) {
        return res.status(400).json({ 
            success: false, 
            message: 'Email is required' 
        });
    }

    try {
        const user = await userModel.findOne({ email });
        
        // Handle user not found with appropriate status
        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'User not found' 
            });
        }

        // Generate 6-digit OTP
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        
        // Set OTP and expiration (fixed expiration time)
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 60000 * 6000; // 1 minute (60,000 ms)
        
        await user.save();
        console.log('do you save?????');

        // Email configuration with improved formatting
        const mailOptions = {
            from: `Healthcare.gov <${process.env.SENDER_EMAIL}>`,
            to: user.email,
            subject: 'Password Reset OTP',
            text: `Hi ${user.name},\n\nYour password reset OTP is: ${otp}\nThis OTP will expire in 10 minutes.`,
            html: `<p>Hi ${user.name},</p>
                   <p>Your password reset OTP is: <strong>${otp}</strong></p>
                   <p>This OTP will expire in 10 minutes.</p>`
        };

        await transporter.sendMail(mailOptions);
        
        // Logging (consider removing in production)
        console.log(`Password reset OTP sent to ${email}: ${otp}`);

        return res.json({ 
            success: true, 
            message: 'OTP sent to your email' 
        });

    } catch (error) {
        console.error('Password reset error:', error);
        return res.status(500).json({ 
            success: false, 
            message: 'Server error. Please try again later.' 
        });
    }
};

export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    // Validate input with proper status code
    if (!email || !otp || !newPassword) {
        return res.status(400).json({
            success: false,
            message: 'Email, OTP, and new password are required'
        });
    }

    try {
        const user = await userModel.findOne({ email });
        
        // Check if user exists
        if (!user) {
            return res.status(404).json({
                success: false,
                message: 'User not found'
            });
        }

        // Verify OTP matches and is not expired
        if (user.resetOtp !== otp) {
            return res.status(401).json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        if (Date.now() > user.resetOtpExpireAt) {
            return res.status(401).json({
                success: false,
                message: 'OTP has expired'
            });
        }

        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        // Update user document
        user.password = hashedPassword;
        user.resetOtp = undefined;  // Clear OTP fields
        user.resetOtpExpireAt = undefined;
        
        await user.save();

        return res.json({
            success: true,
            message: 'Password reset successfully'
        });

    } catch (error) {
        console.error('Password reset error:', error);
        return res.status(500).json({
            success: false,
            message: 'Internal server error'
        });
    }
};
export const generateOTP = () => {
    return Math.floor(1000 + Math.random() * 9000).toString();
};

export const getOtpExpirationTime = ()=>{
    return new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now
}

export const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

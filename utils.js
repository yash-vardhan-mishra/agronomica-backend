exports.generateOTP = () => {
    return Math.floor(1000 + Math.random() * 9000).toString();
};

exports.getOtpExpirationTime = ()=>{
    return new Date(Date.now() + 5 * 60 * 1000); // 5 minutes from now
}

exports.emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

exports.passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&_]{8,}$/;

/**
 * Generates a temporary password.
 *
 * This function creates a random temporary password of 8 characters, which includes a mix of uppercase letters,
 * lowercase letters, numbers, and special characters.
 *
 * @returns {string} - The generated temporary password.
 *
 * @example
 * const tempPassword = generateTempPassword();
 * console.log('Generated temporary password:', tempPassword);
 */
exports.generateTempPassword = () => {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
    let tempPassword = '';
    for (let i = 0; i < 8; i++) {
        const randomIndex = Math.floor(Math.random() * characters.length);
        tempPassword += characters[randomIndex];
    }
    return tempPassword;
};
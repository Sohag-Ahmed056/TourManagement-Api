import bcryptjs from "bcryptjs";
import httpStatus from "http-status-codes";
import { envVars } from "../../config/env";
import AppError from "../../errorHelpers/AppError";
import { generateToken, verifyToken } from "../../utils/jwt";
import { IsActive, IUser } from "../user/user.interface";
import { User } from "../user/user.model";
import { CreateUserToken } from "../../utils/userToken";
import { JwtPayload } from "jsonwebtoken";


const credentialsLogin = async (payload: Partial<IUser>) => {
    const { email, password } = payload;

    const isUserExist = await User.findOne({ email })

    if (!isUserExist) {
        throw new AppError(httpStatus.BAD_REQUEST, "Email does not exist")
    }

    const isPasswordMatched = await bcryptjs.compare(password as string, isUserExist.password as string)

    if (!isPasswordMatched) {
        throw new AppError(httpStatus.BAD_REQUEST, "Incorrect Password")
    }
    // const jwtPayload = {
    //     userId: isUserExist._id,
    //     email: isUserExist.email,
    //     role: isUserExist.role
    // }
    // const accessToken = generateToken(jwtPayload, envVars.JWT_ACCESS_SECRET, envVars.JWT_ACCESS_EXPIRES)
    // const refreshToken = generateToken(jwtPayload, envVars.JWT_REFRESH_SECRET,envVars.JWT_REFRESH_EXPIRES)

    const userTokens = CreateUserToken(isUserExist)

    const {password: pwd, ...userData} = isUserExist.toObject()

    return {
        accesToken: userTokens.accessToken,
        refreshToken: userTokens.refreshToken,
        user: userData
    }

}




const giveAccessToken = async (refreshToken: string) => {
    //verify refresh token
    const verfiedRefreshToken = verifyToken(refreshToken, envVars.JWT_REFRESH_SECRET)

    const isUserExist = await User.findOne({ email: verfiedRefreshToken.email}) 
    if (!isUserExist) {
        throw new AppError(httpStatus.BAD_REQUEST, "Email does not exist")
    }

    if(isUserExist.isActive === IsActive.BLOCKED){
        throw new AppError(httpStatus.FORBIDDEN, "Your account has been blocked. Please contact support.")
    }

   
    const jwtPayload = {
        userId: isUserExist._id,
        email: isUserExist.email,
        role: isUserExist.role
    }
    const accessToken = generateToken(jwtPayload, envVars.JWT_ACCESS_SECRET, envVars.JWT_ACCESS_EXPIRES)
    




    return {
        accessToken
    }

}


//user - login - token (email, role, _id) - booking / payment / booking / payment cancel - token 

export const AuthServices = {
    credentialsLogin,

    getAccessToken: giveAccessToken
}
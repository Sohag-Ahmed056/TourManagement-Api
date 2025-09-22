import { JwtPayload } from "jsonwebtoken";
import { envVars } from "../config/env";
import AppError from "../errorHelpers/AppError";
import { IsActive, IUser } from "../modules/user/user.interface";
import { User } from "../modules/user/user.model";
import { generateToken, verifyToken } from "./jwt";
import httpStatus from "http-status-codes";

export const CreateUserToken =(user: Partial<IUser>)=>{
    const jwtPayload = {
            userId: user._id,
            email: user.email,
            role: user.role
        }
        const accessToken = generateToken(jwtPayload, envVars.JWT_ACCESS_SECRET, envVars.JWT_ACCESS_EXPIRES)
        const refreshToken = generateToken(jwtPayload, envVars.JWT_REFRESH_SECRET,envVars.JWT_REFRESH_EXPIRES)
    
        return{

            accessToken,
            refreshToken
        }




}

    //generate new token
   export const createNewAccessTokenWithRefreshToken =async (refreshToken:string)=>{

         const verfiedRefreshToken = verifyToken(refreshToken, envVars.JWT_REFRESH_SECRET) as JwtPayload

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
        accessToken,
        refreshToken
    }

    }
/* eslint-disable @typescript-eslint/no-unused-vars */
import { NextFunction, Request, Response } from "express"
import httpStatus from "http-status-codes"
import { catchAsync } from "../../utils/catchAsync"
import { sendResponse } from "../../utils/sendResponse"
import { AuthServices } from "./auth.service"
import AppError from "../../errorHelpers/AppError"
import { setAuthcookie } from "../../utils/setCookie"
import { set } from "mongoose"

const credentialsLogin = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const loginInfo = await AuthServices.credentialsLogin(req.body)

            setAuthcookie(res,loginInfo)
   


    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "User Logged In Successfully",
        data: loginInfo,
    })
})




const getAccessToken = catchAsync(async (req: Request, res: Response, next: NextFunction) => {

    const refreshToken= req.cookies.refreshToken
    if(!refreshToken){
        return next(new AppError(httpStatus.BAD_REQUEST, "Please provide refresh token"))
    }
    const TokenInfo = await AuthServices.getAccessToken(refreshToken)

    setAuthcookie(res,TokenInfo.accessToken)

    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "User Logged In Successfully",
        data: TokenInfo,
    })
})


const logout = catchAsync(async (req: Request, res: Response, next: NextFunction) => {


    res.clearCookie("accessToken",{
        httpOnly:true,
        secure:false,
        sameSite:"lax"
    })

    res.clearCookie("refreshToken",{
        httpOnly:true,
        secure:false,
        sameSite:"lax"
    })

}
)


const resetPassword = catchAsync(async (req: Request, res: Response, next: NextFunction) => {

          const newPassword= req.body.newPassword;
          const oldPassword= req.body.oldPassword;
          const decodedToken= req.user;

          await AuthServices.resetPassword(newPassword, oldPassword, decodedToken)



    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "Password successfully changed",
        data: null,
    })

}
)
export const AuthControllers = {
    credentialsLogin,
    getAccessToken,
    logout
}
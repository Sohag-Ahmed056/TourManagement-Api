/* eslint-disable @typescript-eslint/no-unused-vars */
import { NextFunction, Request, Response } from "express"
import httpStatus from "http-status-codes"
import { catchAsync } from "../../utils/catchAsync"
import { sendResponse } from "../../utils/sendResponse"
import { AuthServices } from "./auth.service"
import AppError from "../../errorHelpers/AppError"

const credentialsLogin = catchAsync(async (req: Request, res: Response, next: NextFunction) => {
    const loginInfo = await AuthServices.credentialsLogin(req.body)

    res.cookie("refreshToken", loginInfo.refreshToken,{
        httpOnly:true,
        secure:false,
        
    })

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

    sendResponse(res, {
        success: true,
        statusCode: httpStatus.OK,
        message: "User Logged In Successfully",
        data: TokenInfo,
    })
})


export const AuthControllers = {
    credentialsLogin,
    getAccessToken
}
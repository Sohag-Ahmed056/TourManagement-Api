import { Response } from "express"


export interface TokenInfo {
    accessToken?: string;
    refreshToken?: string;
}
 

export const setAuthcookie = (res:Response, TokenInfo: TokenInfo) => {


    if(TokenInfo.refreshToken){

    res.cookie("refreshToken", TokenInfo.refreshToken,{
        httpOnly:true,
        secure:false,

    })

    }

    if(TokenInfo.accessToken){

    res.cookie("accessToken", TokenInfo.accessToken,{
        httpOnly:true,
        secure:false,

    })
    }
 }
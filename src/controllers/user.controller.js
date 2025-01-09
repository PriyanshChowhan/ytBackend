import { asyncHandler } from "../utils/asynchHandler.js"
import {ApiError} from "../utils/ApiError.js"
import {User} from "../models/user.model.js"
import {uploadOnCloudinary} from "../utils/cloudinary.js"
import {ApiResponse} from "../utils/ApiResponse.js"
import jwt from "jsonwebtoken"
import {verifyJWT} from "../middlewares/auth.middleware.js"
import mongoose from "mongoose"
import bcrypt from "bcrypt"

const generateAccessAndRefreshTokens = async (userId) => {
    try{
        const user = await User.findById(userId)

        const accessToken = user.generateAcessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        user.save({ValiditeBeforeSave : false})

        return {accessToken, refreshToken}
    }

    catch(err){
        throw new ApiError(500, "Something Went wrong")
    }
}

const registerUser = asyncHandler(async (req, res, next) => {
    // get user details from frontend
    // validation
    // check if user already exists : username, email
    // check avatar and images file
    // upload files to cloudinary, avatar
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation
    // return res

    const {fullname, username, email, password} = req.body

    if(
        [fullname, email, username, password].some((field) => {
            field?.trim() == "";
        })
    ){
        throw new ApiError(400, "All fields required.")
    }
    
    const existingUser = await User.findOne({
        $or : [{username} , {email}]
    })

    if(existingUser){
        throw new ApiError(409, "User with email or username already exists")
    }

    const avatarLocalPath = req.files?.avatar[0]?.path
    console.log(req.files)

    const coverImageLocalPath = req.files?.coverImage[0]?.path

    // let coverImageLocalPath;
    // if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
    //     coverImageLocalPath = req.files.coverImage[0].path
    // }

    if(!avatarLocalPath){
        throw new ApiError(400, "Avatar file is required")
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const cover = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")
    }

    if(!cover){
        throw new ApiError(400, "Cover Image file is required")
    }

    const user = await User.create({
        fullname,
        avatar : avatar.url,
        coverImage: cover?.url || "",
        email, 
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )

    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while registering the user")
    }

    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered Successfully")
    )

})

const loginUser = asyncHandler( async(req, res, next) => {
    // req body data
    // usernname or email exist
    // find user
    // pass check
    // access refresh token 
    // send cookie

    
    const {username, password, email} = req.body

    if(!username && !email){
        throw new ApiError(400, "username or email is required.")
    }

    const user = await User.findOne({
        $or : [{username}, {email}]
    })

    if(!user){
        throw new ApiError(404, "User does not exist.")
    }

    
    const isPassValid = await user.isPasswordCorrect(password)

    if(!isPassValid){
        throw new ApiError(401, "Invalid user credential.")
    }

    const {accessToken, refreshToken} = await generateAccessAndRefreshTokens(user._id)

    const loggedInUser = await User.findById(user._id).select("-password -refreshToken")

    const options = {
        httpOnly : true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken, options)
    .json(
        new ApiResponse(
            200, 
            {
                user: loggedInUser, accessToken, refreshToken
            },
            "User logged In Successfully"
        )
    )
})

const logoutUser = asyncHandler( async(req, res, next) => {
    User.findByIdAndUpdate(
        req.user._id,
        {
            $unset : {
                refreshToken : 1
            }
        },
        {
            new : true
        }
    )

    const options = {
        httpOnly : true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken", options)
    .clearCookie("refreshToken", options)
    .json(new ApiResponse(200, {}, "User logged Out"))
})

const refreshAccessToken = asyncHandler( async (req,res,next) => {
    console.log("1")
    const oldRefreshToken = req.cookies.refreshToken
    
    if(!oldRefreshToken){
        throw new ApiError(401, "unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            oldRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if (!user) {
            throw new ApiError(401, "Invalid refresh token")
        }
    
        if (oldRefreshToken !== user?.refreshToken) {
            throw new ApiError(401, "Refresh token is expired or used")   
        }

        const options = {
            httpOnly: true,
            secure: true
        }
    
        const {accessToken, newRefreshToken} = await generateAccessAndRefreshTokens(user._id)
    
        return res
            .status(200)
            .cookie("accessToken", accessToken, options)
            .cookie("refreshToken", newRefreshToken, options)
            .json(
                new ApiResponse(
                    200, 
                    {accessToken, refreshToken: newRefreshToken},
                    "Access token refreshed"
                )
            )
    } catch (error) {
        throw new ApiError(401, error?.message || "Invalid refresh token")
    }
})

const changeCurrentPassword = asyncHandler( async(req,res,next) => {

    const {oldPassword, newPassword} = req.body

    const user = await User.findById(req.user?._id)

    if(!user){
        throw new ApiError(401, "User not found")
    }

    
    const isPassCorrect = await user.isPasswordCorrect(oldPassword)

    if(!isPassCorrect){
        throw new ApiError(400, "Invalid old password")
    }

    user.password = newPassword
    await user.save({validateBeforeSave: false})

    return res
    .status(200)
    .json(new ApiResponse(200, {}, "Password changed successfully"))
})

const getCurrentUser = asyncHandler(async (req, res, next) => {
    return res
    .status(200)
    .json(new ApiResponse(
        200,
        req.user,
        "User fetched succesfully"
    ))
})

const updateAccountDetails = asyncHandler(async (req,res,next) => {
    const {fullname, email} = req.body

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set : {
                fullname,
                email
            }
        },
        {
            new : true
        }
    ).select("-password")

    return res
    .status(200)
    .json(new ApiResponse(200, user, "Account details updated successfully"))
})

const updateUserAvatar = asyncHandler( async(req, res, next) => {
    const newAvatarLocalPath = req.file?.path

    if(!newAvatarLocalPath){
        throw new ApiError(400, "Avatar image is required.")
    }

    const uploadAvatar = await uploadOnCloudinary(newAvatarLocalPath)

    if(!uploadAvatar.url){
        throw new ApiError(400, "Error while uploading on avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set : { avatar: uploadAvatar.url }
        },
        {
            new:true
        }
    ).select('-password')

    if(!user){
        throw new ApiError(500, "Internal server error")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Avatar image updated successfully")
    )
})

const updateUserCoverImage = asyncHandler( async(req,res,next) => {
    const newCoverLocalPath = req.file?.path

    if(!newCoverLocalPath){
        throw new ApiError(400, "Cover image is required.")
    }

    const uploadCover = await uploadOnCloudinary(newCoverLocalPath)

    if(!uploadCover.url){
        throw new ApiError(400, "Error while uploading on Cover")
    }

    const user = await User.findByIdAndUpdate(
        req.user._id,
        {
            $set : { coverImage: uploadCover.url }
        },
        {
            new:true
        }
    ).select('-password')

    if(!user){
        throw new ApiError(500, "Internal server error")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200, user, "Cover image updated successfully")
    )
})
export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    changeCurrentPassword,
    getCurrentUser,
    updateAccountDetails,
    updateUserAvatar,
    updateUserCoverImage
    // getUserChannelProfile,
    // getWatchHistory,
}
import dotenv from "dotenv"
import express from "express"
import connectDB from "./db/index.js"
import {app} from "./app.js"

dotenv.config()
connectDB()
.then(() => {
    app.listen(process.env.PORT || 8000, () => {
        console.log(`⚙️  Server is running at port : ${process.env.PORT}`)
    })
})
.catch((err) => {
    console.log("MONGO db connection failed !!! ", err);
})

// (async () => {
//     try{
//         await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
//         app.on("error", (error) => {
//             console.log("Error");
//             throw error
//         })

//         app.listen(process.env.PORT, () => {
//             console.log(`App is listening on ${process.env.PORT}`)
//         })
//     }
//     catch(error){
//         console.error("ERROR :", error)
//         throw error
//     }
// })()
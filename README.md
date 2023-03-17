# Password-Manager
A full stack Golang password manager that uses a CLI Golang frontend, a Golang backend, and MongoDB database. This is the backend portion of a 2 part Password Manager Web app. The front-end of this web server can be found [here](https://github.com/zacharyLYH/Password-Manager-CLI).

# Just another iteration of a password manager? 
Kinda. The motivation behind this project was personal; I was looking for a free web hosted password manager but the ones I found that were web hosted required a monthly subscription. While it is indeed just another password manager, the intention of this project is to build an open source, web hosted, and most importantly ***secure*** password manager. If a password manager is not so much what you desire, with the way this project is built you may extrapolate the secure features of this project to build whatever you need - digital notes, a digital vault etc. 

# Disclaimer
I will not be providing a usable database instance. The reason is that while the design is sound, it is probable there are means of attack that I'm not aware of, and giving access to my MongoDB instance might be dangerous for the security of my passwords. However, I will link a good tutorial on how to get a MongoDB instance set up for your use. I will also not be providing the URL for accessing my hosted server, due to the fear of folks spamming requests and racking up my server costs. I will also link a good tutorial on setting a server youself. That said, anybody that adopts my implementation for their own password managing needs is liable for any theft of property happening to them. Keep your network and your access keys safe, and adapt this code to further enhance your security needs. 

# High level overview 
Roughly speaking, this project takes great inspiration from the SSH protocols. On a high level, this is the intended flow of the service:
1) Users log in and sends credentials over using RSA encryption
2) Server receives log in information, and upon succesful authentication sends back an encrypted Symmetric Key
3) Here on out any communication between parties utilizes this Symmetric Key

The frontend is a Golang CLI app. A user is expected to interact with the CLI app using a set of commands we'll define later. The backend is a Go server, nothing much to talk about there. The database we're using is a MongoDB database, and we'll use of 3 types of documents, a SymMap, UserData, and Password document. 

Now, we'll discuss the various functions and implementation detail on each end and the database design, and go on tangents at appropriate moments to further explain details or discuss security features.

# Key terms
- ttl : The time to live variable. Stored on the frontend. This is an approximation of a session cookie, where we'll time out the service and perform necessary clean ups to avoid memory leakage. Initially 0. 
- symKey : A secret symmetric key that will be previously exchanged by the client and server. 
- serverPubKey : The Golang backend server's public key. Used by the CLI app to perform RSA encryption before a symKey is produced. 
- desktopPub : The CLI app's public key.
- desktopPriv : The CLI app's private key
- username : The username of this user on this app. This field is unique for all accounts, thus works well as an identifier.
- storedUsername : The username we're logged in as, stored on the frontend. Is also meant to be used to emulate the use of a cookie. Initially an empty string. 
- serverSalt : A private string of characters stored on the server that will be used as salt for data that requires salting.
- id : For any user User, an id is a counter from 1 till the number of Password documents this User has, that acts as an easy identifier for both the client and server to refer to a particular Password document. 
- AES : A commonly used symmetric encryption algorithm. In this implementation, we'll be using some content as payload and a `symKey` as the hashing key. 
- RSA : An asymmetric encrypting algorithm. We'll be using RSA during the absence of `symKey`s, that is, before the symmetric key exchange. 

# MongoDB database
### SymMap
> Recall that a new symmetric key is given to the user at each log in, thus we need a way to keep track of the symmetric being while the session is active. 
> This object gets removed as soon as a SIGTERM is sent to the frontend which will trigger a request to remove this SymMap. 
> 
- username
- symKey
- desktopPub

### UserData
> Here is where we store the user's identifying information, not their passwords. 
> Note that only the login password is stored here as the RSA encryption of the user's raw password and the backend's public key.

- username
- loginPassword
  - raw password is JWT encrypted with the `serverPrivKey`
- array of ***Password*** MongoDB IDs
  - Password is the object where the user's passwords are actually stored
- entriesCount
  - The number of entries in the array of Password

### Password
- id
  - Not the Mongo document ID automatically assigned. This is a self assigned, numerically from 1 to the number of documents for each Password object related to this user. 
  - If we delete a document from the middle of the pack, the last Password objects gets reassigned to this id. 
- description
- encryptedUsername
  - raw username is JWT encrypted with the `serverPrivKey`
- encryptedPassword
  - raw password is JWT encrypted with the `serverPrivKey`

# Backend side implementation
## Prerequisite
1. Have the latest version of Go installed
2. In your terminal, run the following commands
```
go env -w GO111MODULE=on
go mod tidy
go mod init quickstart
go get go.mongodb.org/mongo-driver
```

## Variables
- `symKey`
- `serverPubKey`
- `serverPrivKey`
- `serverSalt`

### Check username availability
- Recall that usernames must be unique, this API will do just that. 
- This API will only be used in [this function](###sign-up-frontend)

### Sign up backend
- Input `username`, `signUpPassword`
- Create a new UserData Mongo document
- Notice that `signUpPassword` is already an RSA encryption of the `serverPubKey` and the raw password
  - RSA decrypt `signUpPassword` using `serverPrivKey`, generating `rawPass`
  - JWT encrypt `rawPass` and `serverPrivKey` and store this encryption as `loginPassword` for this `username`
- Output true on success false otherwise

### Login
- Input `username`, `loginPassword`, `desktopPub`
- Lookup this `username` and verify their `loginPassword`
  - RSA decrypt `loginPassword` using `serverPrivKey`, generating `rawPass`
  - AES decrypt this user's *stored* `accountPassword` (not to be confused with the input loginPassword) with `serverSalt`
    - If the encryption matches then this user is authenticated
- Generate a random `symKey`
- Create a SymMap entry using `username : symKey`
- RSA decrypt `initialSecuritySet` to obtain the `nonce` and `initSym` values
- Send back the `symKey` AES encrypted using `initSym` value 
- Output `symKeyHash`

### Get all descriptions for username
- Input `storedUsername`
- Pull all Password documents for this `storedUsername`
- For each Password document, start a priority queue of (id, description), call this descriptions
- Output: descriptions
- The idea is that using this function, users can figure out the id for the username-password combination they're interested in.

### Create a Password object
- Input `storedUsername`, `hashPassword`, `hashSiteUserName`, `description`
- Pull the `symKey` for `storedUsername`
- Decrypt `hashPassword` and `hashsiteUserName` 
  - rawPass = *aesDecrypt*(`hashPassword`,`symKey`)
  - rawSiteUserName = *aesDecrypt*(`hashSiteUserName`,`symKey`)
  - storePass = *aesEncrypt*(rawPass, serverPubKey)
  - storeSiteUserName = *aesEncrypt*(rawSiteUsername, serverPubKey)
- Create this Password object using storePass and storeSiteUserName
- Store the Mongo ObjectID of this object into the UserData's array of Passwords
- Increment `entriesCount` 
- Output true on success false otherwise

### Update a siteUserName or password pair for Password
- Input `storedUsername`, `hashPassword`, `hashSiteUserName`, `description`, `id`
- Check that at least one of `hashPassword`, `hashsiteUserName`, `description` is filled
- Use `storedUsername` and `id` to pull Password
  - Pull out `symKey`
  - rawPass = *aesDecrypt*(`hashPassword`, `symKey`)
  - rawSiteUsername = *aesDecrypt*(`hashSiteUserName`, `symKey`)
  - storePass = *aesEncrypt* (rawPass, `serverPrivKey`)
  - storeSiteUserName = *aesEncrypt* (rawSiteUsername, `serverPrivKey`)
- Update this Password object using storePass and storeSiteUserName
  - If `description` wasn't provided, reuse the old description
- Output true on success false otherwise

### Get a password
- Input `storedUsername`, `id`
- Pull the `symKey` associated with this `storedUsername`
- Pull the right Password document, pull `storedUsername` and `storedPassword`
  - rawPass = *aesDecrypt*(`storedPassword`, `serverPrivKey`)
  - rawSiteUsername = *aesDecrypt*(`storedUsername`, `serverPrivKey`)
  - sendPass = *aesEncrypt*(rawPass, `symKey`)
  - sendUsername = *aesEncrypt*(rawSiteUsername, `symKey`)
  - receivedUsernameAndPassword = [sendUsername, sendPass]
- Output receivedUsernameAndPassword

### Clear symMap
- Input `storedUsername`
- Clear the SymMap for `storedUsername`
- Output nothing

### Delete a Password object
- Input `storedUsername`, `id`
- Go to Password and remove this object
- Find the Password with `entriesCount` and set its id to the recently deleted input `id`
- Decrement `entriesCount` 
- Output true on success false otherwise

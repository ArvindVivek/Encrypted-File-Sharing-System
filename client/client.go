package client

// CS 161 Project 2

// You MUST NOT change these default imports. ANY additional imports
// may break the autograder!

import (
	"encoding/hex"
	"encoding/json"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	// hex.EncodeToString(...) is useful for converting []byte to string

	// Useful for formatting strings (e.g. `fmt.Sprintf`).
	"fmt"

	// Useful for creating new error messages to return using errors.New("...")
	"errors"

	// Optional.
	_ "strconv"
)

// This serves two purposes: it shows you a few useful primitives,
// and suppresses warnings for imports not being used. It can be
// safely deleted!
func someUsefulThings() {

	// Creates a random UUID.
	randomUUID := uuid.New()

	// Prints the UUID as a string. %v prints the value in a default format.
	// See https://pkg.go.dev/fmt#hdr-Printing for all Golang format string flags.
	userlib.DebugMsg("Random UUID: %v", randomUUID.String())

	// Creates a UUID deterministically, from a sequence of bytes.
	hash := userlib.Hash([]byte("user-structs/alice"))
	deterministicUUID, err := uuid.FromBytes(hash[:16])
	if err != nil {
		// Normally, we would `return err` here. But, since this function doesn't return anything,
		// we can just panic to terminate execution. ALWAYS, ALWAYS, ALWAYS check for errors! Your
		// code should have hundreds of "if err != nil { return err }" statements by the end of this
		// project. You probably want to avoid using panic statements in your own code.
		panic(errors.New("An error occurred while generating a UUID: " + err.Error()))
	}
	userlib.DebugMsg("Deterministic UUID: %v", deterministicUUID.String())

	// Declares a Course struct type, creates an instance of it, and marshals it into JSON.
	type Course struct {
		name      string
		professor []byte
	}

	course := Course{"CS 161", []byte("Nicholas Weaver")}
	courseBytes, err := json.Marshal(course)
	if err != nil {
		panic(err)
	}

	userlib.DebugMsg("Struct: %v", course)
	userlib.DebugMsg("JSON Data: %v", courseBytes)

	// Generate a random private/public keypair.
	// The "_" indicates that we don't check for the error case here.
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("PKE Key Pair: (%v, %v)", pk, sk)

	// Here's an example of how to use HBKDF to generate a new key from an input key.
	// Tip: generate a new key everywhere you possibly can! It's easier to generate new keys on the fly
	// instead of trying to think about all of the ways a key reuse attack could be performed. It's also easier to
	// store one key and derive multiple keys from that one key, rather than
	originalKey := userlib.RandomBytes(16)
	derivedKey, err := userlib.HashKDF(originalKey, []byte("mac-key"))
	if err != nil {
		panic(err)
	}
	userlib.DebugMsg("Original Key: %v", originalKey)
	userlib.DebugMsg("Derived Key: %v", derivedKey)

	// A couple of tips on converting between string and []byte:
	// To convert from string to []byte, use []byte("some-string-here")
	// To convert from []byte to string for debugging, use fmt.Sprintf("hello world: %s", some_byte_arr).
	// To convert from []byte to string for use in a hashmap, use hex.EncodeToString(some_byte_arr).
	// When frequently converting between []byte and string, just marshal and unmarshal the data.
	//
	// Read more: https://go.dev/blog/strings

	// Here's an example of string interpolation!
	_ = fmt.Sprintf("%s_%d", "file", 1)
}

// This is the type definition for the User struct.
// A Go struct is like a Python or Java class - it can have attributes
// (e.g. like the Username attribute) and methods (e.g. like the StoreFile method below).
type User struct {
	Username     []byte
	Password     []byte
	SK           []byte
	FilesToKeys  map[string][]byte
	FilesToAuths map[string]string
	// You can add other attributes here if you want! But note that in order for attributes to
	// be included when this struct is serialized to/from JSON, they must be capitalized.
	// On the flipside, if you have an attribute that you want to be able to access from
	// this struct's methods, but you DON'T want that value to be included in the serialized value
	// of this struct that's stored in datastore, then you can use a "private" variable (e.g. one that
	// begins with a lowercase letter).
}

type File struct {
	Filename string
	Content  []byte
	RootUUID uuid.UUID
	NextUUID uuid.UUID
	LastUUID uuid.UUID
}

type Authorization struct {
	IsRoot   bool
	Username string
	Key      []byte
	FileID   uuid.UUID
	Children map[string]string
}

func (auth *Authorization) ChangeSymKeyAndFileID(root *User, filename string, keynew []byte) (err error) {
	auth.Key = keynew
	auth.FileID = uuid.New()
	for username_hash, id := range auth.Children {
		// Download child authorization
		id_to_uuid, err := uuid.FromBytes([]byte(id)[:16])
		if err != nil {
			return errors.New("could not convert id into a uuid.UUID")
		}
		download_data, ok := userlib.DatastoreGet(id_to_uuid)
		if !ok {
			return errors.New("Could not download child authorization.")
		}

		// Decrypt child authorization
		key, err := userlib.HashKDF(root.FilesToKeys[filename], []byte(username_hash))
		if err != nil {
			return errors.New("Could not derive a child key.")
		}
		key = key[:16]
		decryption := userlib.SymDec(key, download_data)

		// Unmarshal child authorization
		var child Authorization
		err = json.Unmarshal(decryption, &child)
		if err != nil {
			return errors.New("Could not unmarshal child authorization.")
		}

		// Get child HMAC
		hmac_UUID, err := uuid.FromBytes(userlib.Hash([]byte(id))[:16])
		if err != nil {
			return errors.New("Could not generate a valid HMAC UUID from the given child's username")
		}
		download_hmac, ok := userlib.DatastoreGet(hmac_UUID)
		if !ok {
			return errors.New("Could not unmarshal child authorization's HMAC.")
		}

		// Unmarshal child HMAC
		var hmac_then []byte
		err = json.Unmarshal(download_hmac, &hmac_then)
		if err != nil {
			return errors.New("Could not unmarshal child HMAC.")
		}

		// Compare HMACs
		hmac_now, err := userlib.HMACEval(child.Key, download_data)
		if err != nil {
			return errors.New("Could not compute HMAC for child authorization.")
		}
		if !userlib.HMACEqual(hmac_now, hmac_then) {
			return errors.New("Child authorization has been compromised.")
		}

		// Update key and file ID
		child.Key = keynew
		child.FileID = auth.FileID

		// Remarshal child authorization
		marshal, err := json.Marshal(child)
		if err != nil {
			return errors.New("Could not marshal child authorization.")
		}

		// Encrypt child authorization
		upload_data := userlib.SymEnc(key, make([]byte, 16), marshal)

		// Upload child authorization
		userlib.DatastoreSet(id_to_uuid, upload_data)

		// Update HMAC
		hmac_now, err = userlib.HMACEval(child.Key, upload_data)
		if err != nil {
			return errors.New("Could not compute HMAC for child authorization (2).")
		}
		userlib.DatastoreSet(hmac_UUID, hmac_now)
	}

	return nil
}

func (auth *Authorization) RevokeUser(root *User, filename string, username_hash string) (err error) {
	id, ok := auth.Children[username_hash]
	if !ok {
		return errors.New("No child exists with the specified username hash.")
	}
	// Delete child authorization
	auth_id, err := uuid.FromBytes([]byte(id)[:16])
	if err != nil {
		return errors.New("Could not generate a valid UUID from the given child's username.")
	}
	userlib.DatastoreDelete(auth_id)
	// Delete child authorization's HMAC
	hmac_id, err := uuid.FromBytes(userlib.Hash([]byte(id))[:16])
	if err != nil {
		return errors.New("Could not generate a valid HMAC UUID from the given child's username.")
	}
	userlib.DatastoreDelete(hmac_id)
	// Remove child from auth.Children
	delete(auth.Children, username_hash)
	auth.ChangeSymKeyAndFileID(root, filename, userlib.RandomBytes(16))

	return nil
}

type Invitation struct {
	FileID        uuid.UUID
	SK            []byte
	SenderHash    string
	RecipientHash string
	ParentAuth    Authorization
	ParentPreUUID string
	ParentKey     []byte
}

// NOTE: The following methods have toy (insecure!) implementations.

func InitUser(username string, password string) (userdataptr *User, err error) {
	/*var userdata User
	userdata.Username = username
	return &userdata, nil*/
	if len(username) == 0 {
		return nil, errors.New("username is empty")
	}

	userHash := userlib.Hash([]byte(username))
	passHash := userlib.Hash([]byte(password))
	user := User{
		Username:     userHash,
		Password:     passHash,
		SK:           userlib.Argon2Key(passHash, userHash, 16),
		FilesToKeys:  make(map[string][]byte),
		FilesToAuths: make(map[string]string),
	}

	u, e := uuid.FromBytes(userHash[:16])
	if e != nil {
		return nil, e
	}

	_, userExists := userlib.DatastoreGet(u)
	if userExists {
		return nil, errors.New("username exists")
	}

	userJson, e2 := json.Marshal((user))
	if e2 != nil {
		return nil, e
	}
	userlib.DatastoreSet(u, userlib.SymEnc(user.SK, make([]byte, 16), userJson))

	u2, e3 := uuid.FromBytes(userlib.Hash(userlib.Hash([]byte(username)))[:16])
	if e3 != nil {
		return nil, e3
	}

	userHMAC, e4 := userlib.HMACEval(user.SK, userlib.SymEnc(user.SK, make([]byte, 16), userJson))
	if e4 != nil {
		return nil, e4
	}
	userlib.DatastoreSet(u2, userHMAC)

	return &user, nil
}

func GetUser(username string, password string) (userdataptr *User, err error) {
	/*var userdata User
	userdataptr = &userdata
	return userdataptr, nil*/
	// Download user
	id, err := uuid.FromBytes(userlib.Hash([]byte(username))[:16])
	if err != nil {
		return nil, errors.New("Could not generate a valid UUID from the given username.")
	}
	download_user, ok := userlib.DatastoreGet(id)
	if !ok {
		return nil, errors.New("Could not download user.")
	}

	// Decrypt user
	secretKey := userlib.Argon2Key(userlib.Hash([]byte(password)), userlib.Hash([]byte(username)), 16)
	user_marshal := userlib.SymDec(secretKey, download_user)

	// Verify HMAC
	hmac_id, err := uuid.FromBytes(userlib.Hash(userlib.Hash([]byte(username)))[:16])
	if err != nil {
		return nil, errors.New("Could not generate a valid HMAC UUID from the given username.")
	}
	hmac_then, ok := userlib.DatastoreGet(hmac_id)
	if !ok {
		return nil, errors.New("Could not download user's HMAC.")
	}
	hmac_now, err := userlib.HMACEval(secretKey, download_user)
	if err != nil {
		return nil, errors.New("Could not generate a HMAC for the given user.")
	}
	if !userlib.HMACEqual(hmac_now, hmac_then) {
		return nil, errors.New("User has been compromised.")
	}

	// Unmarshal user
	var user User
	err = json.Unmarshal(user_marshal, &user)
	if err != nil {
		return nil, errors.New("Could not unmarshal user.")
	}

	// This is fine, as go should automatically allocate user on the heap
	return &user, nil
}

func (userdata *User) StoreFile(filename string, content []byte) (err error) {
	/*storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return err
	}
	contentBytes, err := json.Marshal(content)
	if err != nil {
		return err
	}
	userlib.DatastoreSet(storageKey, contentBytes)
	return*/

	// Verify that user has not been compromised
	id, err := uuid.FromBytes([]byte(userdata.Username)[:16])
	if err != nil {
		return errors.New("Could not generate a valid UUID from the given username.")
	}
	download_user, ok := userlib.DatastoreGet(id)
	if !ok {
		return errors.New("Could not download user.")
	}

	// Generate SK
	secretKey := userlib.Argon2Key([]byte(userdata.Password), []byte(userdata.Username), 16)

	// Verify HMAC
	hmac_id, err := uuid.FromBytes(userlib.Hash([]byte(userdata.Username))[:16])
	if err != nil {
		return errors.New("Could not generate a valid HMAC UUID from the given username.")
	}
	hmac_then, ok := userlib.DatastoreGet(hmac_id)
	if !ok {
		return errors.New("Could not download user's HMAC.")
	}
	hmac_now, err := userlib.HMACEval(secretKey, download_user)
	if err != nil {
		return errors.New("Could not generate a HMAC for the given user.")
	}
	if !userlib.HMACEqual(hmac_now, hmac_then) {
		return errors.New("User has been compromised.")
	}

	U := uuid.New()
	fileHash := userlib.Hash([]byte(filename))
	userdata.FilesToKeys[hex.EncodeToString(fileHash)] = userlib.RandomBytes(16)
	au := Authorization{
		Key:      userlib.RandomBytes(16),
		FileID:   U,
		Username: hex.EncodeToString(userdata.Username),
		Children: make(map[string]string),
		IsRoot:   true,
	}

	userdata.FilesToAuths[hex.EncodeToString(fileHash)] = hex.EncodeToString(userdata.Username[:8]) + hex.EncodeToString(fileHash[:8])

	keyFileHash := userlib.Hash([]byte(userdata.FilesToAuths[hex.EncodeToString(fileHash)]))
	keyFileUUID, e := uuid.FromBytes(keyFileHash[:16])
	if e != nil {
		return e
	}

	authJSON, e2 := json.Marshal((au))
	if e2 != nil {
		return e2
	}

	authEnc := userlib.SymEnc(userdata.FilesToKeys[hex.EncodeToString(fileHash)], make([]byte, 16), authJSON)
	hmacAuth, e3 := userlib.HMACEval(userdata.FilesToKeys[hex.EncodeToString(fileHash)], authEnc)
	if e3 != nil {
		return e3
	}
	userlib.DatastoreSet(keyFileUUID, hmacAuth)

	authEncUUID, e5 := uuid.FromBytes([]byte(userdata.FilesToAuths[hex.EncodeToString(fileHash)])[:16])
	if e5 != nil {
		return e5
	}

	f := File{
		Filename: filename,
		Content:  content,
		RootUUID: authEncUUID,
		NextUUID: uuid.Nil,
		LastUUID: au.FileID,
	}

	fileJSON, e4 := json.Marshal(f)
	if e4 != nil {
		return e4
	}
	fileEnc := userlib.SymEnc(au.Key, make([]byte, 16), fileJSON)
	userlib.DatastoreSet(au.FileID, fileEnc)

	userlib.DatastoreSet(authEncUUID, authEnc)

	// Update user in datastore
	userHash := userdata.Username

	u, e := uuid.FromBytes(userHash[:16])
	if e != nil {
		return e
	}

	userJson, e2 := json.Marshal(userdata)
	if e2 != nil {
		return e2
	}
	userlib.DatastoreSet(u, userlib.SymEnc(userdata.SK, make([]byte, 16), userJson))

	u2, e3 := uuid.FromBytes(userlib.Hash(userdata.Username)[:16])
	if e3 != nil {
		return e3
	}

	// Update user HMAC in datastore
	userHMAC, e4 := userlib.HMACEval(userdata.SK, userlib.SymEnc(userdata.SK, make([]byte, 16), userJson))
	if e4 != nil {
		return e4
	}
	userlib.DatastoreSet(u2, userHMAC)

	return nil
}

func (userdata *User) AppendToFile(filename string, content []byte) error {
	/*return nil*/
	fileHash := userlib.Hash([]byte(filename))
	fileKey := userdata.FilesToKeys[hex.EncodeToString(fileHash)]
	if fileKey == nil {
		return errors.New("file does not exist for user")
	}
	authEncUUID, e := uuid.FromBytes([]byte(userdata.FilesToAuths[hex.EncodeToString(fileHash)])[:16])
	if e != nil {
		return e
	}
	authEnc, e2 := userlib.DatastoreGet(authEncUUID)
	if e2 == false {
		return errors.New("Access revoked")
	}

	authDec := userlib.SymDec([]byte(userdata.FilesToKeys[hex.EncodeToString(fileHash)]), authEnc)
	var auth Authorization
	e4 := json.Unmarshal(authDec, &auth)
	if e4 != nil {
		return e4
	}

	hmacAuthCurr, e3 := userlib.HMACEval(userdata.FilesToKeys[hex.EncodeToString(fileHash)], authEnc)
	if e3 != nil {
		return e3
	}

	keyFileHash := userlib.Hash([]byte(userdata.FilesToAuths[hex.EncodeToString(fileHash)]))
	keyFileUUID, e5 := uuid.FromBytes(keyFileHash[:16])
	if e5 != nil {
		return e5
	}
	hmacAuthStore, ok := userlib.DatastoreGet(keyFileUUID)
	if ok == false {
		return errors.New("auth hmac does not exist")
	}

	if !userlib.HMACEqual(hmacAuthCurr, hmacAuthStore) {
		return errors.New("auth integrity compromised")
	}

	fileEnc, ok2 := userlib.DatastoreGet(auth.FileID)
	if ok2 == false {
		return errors.New("file does not exist")
	}

	fileDec := userlib.SymDec(auth.Key, fileEnc)
	var file File
	e6 := json.Unmarshal(fileDec, &file)
	if e6 != nil {
		return e6
	}

	f2 := File{
		Filename: filename,
		Content:  content,
		RootUUID: authEncUUID,
		NextUUID: uuid.Nil,
		LastUUID: auth.FileID,
	}

	U2 := uuid.New()
	oldLast := file.LastUUID

	lastFileEnc, ok3 := userlib.DatastoreGet(file.LastUUID)
	if ok3 == false {
		return errors.New("last file does not exist")
	}

	lastFileDec := userlib.SymDec(auth.Key, lastFileEnc)
	var lastFile File
	e7 := json.Unmarshal(lastFileDec, &lastFile)
	if e7 != nil {
		return e7
	}

	fileIDEqual := false
	if auth.FileID == file.LastUUID {
		fileIDEqual = true
		file.NextUUID = U2
	} else {
		lastFile.NextUUID = U2
	}

	file.LastUUID = U2

	fileJSON, e8 := json.Marshal(file)
	if e8 != nil {
		return e8
	}
	fileEnc3 := userlib.SymEnc(auth.Key, make([]byte, 16), fileJSON)
	userlib.DatastoreSet(auth.FileID, fileEnc3)

	fileJSON2, e9 := json.Marshal(f2)
	if e9 != nil {
		return e9
	}
	fileEnc2 := userlib.SymEnc(auth.Key, make([]byte, 16), fileJSON2)
	userlib.DatastoreSet(U2, fileEnc2)

	if !fileIDEqual {
		fileJSON3, e10 := json.Marshal(lastFile)
		if e10 != nil {
			return e10
		}
		fileEnc4 := userlib.SymEnc(auth.Key, make([]byte, 16), fileJSON3)
		userlib.DatastoreSet(oldLast, fileEnc4)
	}

	// Update user in datastore
	userHash := userdata.Username

	u, e := uuid.FromBytes(userHash[:16])
	if e != nil {
		return e
	}

	userJson, ee2 := json.Marshal(userdata)
	if ee2 != nil {
		return ee2
	}
	userlib.DatastoreSet(u, userlib.SymEnc(userdata.SK, make([]byte, 16), userJson))

	u2, e3 := uuid.FromBytes(userlib.Hash(userdata.Username)[:16])
	if e3 != nil {
		return e3
	}

	// Update user HMAC in datastore
	userHMAC, e4 := userlib.HMACEval(userdata.SK, userlib.SymEnc(userdata.SK, make([]byte, 16), userJson))
	if e4 != nil {
		return e4
	}
	userlib.DatastoreSet(u2, userHMAC)

	return nil
}

func (userdata *User) LoadFile(filename string) (content []byte, err error) {
	/*storageKey, err := uuid.FromBytes(userlib.Hash([]byte(filename + userdata.Username))[:16])
	if err != nil {
		return nil, err
	}
	dataJSON, ok := userlib.DatastoreGet(storageKey)
	if !ok {
		return nil, errors.New(strings.ToTitle("file not found"))
	}
	err = json.Unmarshal(dataJSON, &content)
	return content, err*/
	fileHash := userlib.Hash([]byte(filename))
	fileKey := userdata.FilesToKeys[hex.EncodeToString(fileHash)]
	if fileKey == nil {
		return nil, errors.New("file does not exist for user")
	}
	authEncUUID, e := uuid.FromBytes([]byte(userdata.FilesToAuths[hex.EncodeToString(fileHash)])[:16])
	if e != nil {
		return nil, e
	}
	authEnc, e2 := userlib.DatastoreGet(authEncUUID)
	if e2 == false {
		return nil, errors.New("Access revoked")
	}

	authDec := userlib.SymDec([]byte(userdata.FilesToKeys[hex.EncodeToString(fileHash)]), authEnc)
	var auth Authorization
	e4 := json.Unmarshal(authDec, &auth)
	if e4 != nil {
		return nil, e4
	}

	hmacAuthCurr, e3 := userlib.HMACEval(userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))], authEnc)
	if e3 != nil {
		return nil, e3
	}

	keyFileHash := userlib.Hash([]byte(userdata.FilesToAuths[hex.EncodeToString(fileHash)]))
	keyFileUUID, e5 := uuid.FromBytes(keyFileHash[:16])
	if e5 != nil {
		return nil, e5
	}
	hmacAuthStore, ok := userlib.DatastoreGet(keyFileUUID)
	if ok == false {
		return nil, errors.New("auth hmac does not exist")
	}

	if !userlib.HMACEqual(hmacAuthCurr, hmacAuthStore) {
		return nil, errors.New("auth integrity compromised")
	}

	fileEnc, ok2 := userlib.DatastoreGet(auth.FileID)
	if ok2 == false {
		return nil, errors.New("file does not exist")
	}

	fileDec := userlib.SymDec(auth.Key, fileEnc)
	var file File
	e6 := json.Unmarshal(fileDec, &file)
	if e6 != nil {
		return nil, e6
	}

	fileContent := file.Content
	tempFile := file
	for tempFile.NextUUID != uuid.Nil {
		tempFileEnc, ok3 := userlib.DatastoreGet(tempFile.NextUUID)
		if ok3 == false {
			return nil, errors.New("next file not found")
		}
		tempFileDec := userlib.SymDec(auth.Key, tempFileEnc)
		var tempFile2 File
		e7 := json.Unmarshal(tempFileDec, &tempFile2)
		if e7 != nil {
			return nil, e7
		}
		fileContent = append(fileContent, tempFile2.Content...)
		tempFile = tempFile2
	}

	return fileContent, nil
}

func (userdata *User) CreateInvitation(filename string, recipientUsername string) (
	invitationPtr uuid.UUID, err error) {
	// Download user
	id, err := uuid.FromBytes(userdata.Username[:16])
	if err != nil {
		return uuid.Nil, errors.New("Could not generate a valid UUID from the given username.")
	}
	userdata_enc, ok := userlib.DatastoreGet(id)
	if !ok {
		return uuid.Nil, errors.New("Could not download user.")
	}

	rUserHash := userlib.Hash([]byte(recipientUsername))
	id2, err := uuid.FromBytes(rUserHash[:16])
	if err != nil {
		return uuid.Nil, errors.New("Could not generate a valid UUID from the given recipient username.")
	}

	// Decrypt user
	secretKey := userlib.Argon2Key(userdata.Password, userdata.Username, 16)
	user_marshal := userlib.SymDec(secretKey, userdata_enc)

	// Verify HMAC
	hmac_id, err := uuid.FromBytes(userlib.Hash(userdata.Username)[:16])
	if err != nil {
		return uuid.Nil, errors.New("Could not generate a valid HMAC UUID from the given username.")
	}
	hmac_then, ok := userlib.DatastoreGet(hmac_id)
	if !ok {
		return uuid.Nil, errors.New("Could not download user's HMAC.")
	}
	hmac_now, err := userlib.HMACEval(secretKey, userdata_enc)
	if err != nil {
		return uuid.Nil, errors.New("Could not generate a HMAC for the given user.")
	}
	if !userlib.HMACEqual(hmac_now, hmac_then) {
		return uuid.Nil, errors.New("User has been compromised.")
	}

	// Unmarshal user
	err = json.Unmarshal(user_marshal, &userdata)
	if err != nil {
		return uuid.Nil, errors.New("Could not unmarshal user.")
	}

	_, ok = userlib.DatastoreGet(id2)
	if !ok {
		return uuid.Nil, errors.New("Recipient user does not exist")
	}

	fileHash := userlib.Hash([]byte(filename))
	_, ok = userdata.FilesToAuths[hex.EncodeToString(fileHash)]
	userlib.DebugMsg("DEBUG: " + filename)
	if !ok {
		return uuid.Nil, errors.New("Filename does not exist is user's namespace")
	}

	invitationPtr = uuid.New()

	id, err = uuid.FromBytes(([]byte(userdata.FilesToAuths[hex.EncodeToString(userlib.Hash([]byte(filename)))]))[:16])
	if err != nil {
		return uuid.Nil, errors.New("Could not find a valid authorization UUID for the given filename.")
	}

	// Download authorization hash
	auth_enc, ok := userlib.DatastoreGet(id)
	if !ok {
		return uuid.Nil, errors.New("Could not download the file's authorization hash.")
	}

	// Decrypt authorization
	key := userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))]
	decryption := userlib.SymDec(key, auth_enc)

	// Verify HMAC
	hmac_id, err = uuid.FromBytes(userlib.Hash([]byte(userdata.FilesToAuths[hex.EncodeToString(userlib.Hash([]byte(filename)))]))[:16])
	if err != nil {
		return uuid.Nil, errors.New("Could not find a valid authorization HMAC UUID for the given filename.")
	}
	hmac_then, ok = userlib.DatastoreGet(hmac_id)
	if !ok {
		return uuid.Nil, errors.New("Could not download the authorization's HMAC.")
	}
	hmac_now, err = userlib.HMACEval(key, auth_enc)
	if err != nil {
		return uuid.Nil, errors.New("Could not generate a HMAC for the given user and file's authorization.")
	}

	if !userlib.HMACEqual(hmac_now, hmac_then) {
		return uuid.Nil, errors.New("The authorization for this user and file has been compromised.")
	}

	// Unmarshal authorization
	var auth Authorization
	err = json.Unmarshal(decryption, &auth)
	if err != nil {
		return uuid.Nil, errors.New("Could not unmarshal the authorization.")
	}

	// Create invitation
	var inv Invitation
	inv.FileID = auth.FileID
	inv.SK = auth.Key
	inv.SenderHash = hex.EncodeToString(userdata.Username)
	inv.RecipientHash = hex.EncodeToString(userlib.Hash([]byte(recipientUsername)))
	inv.ParentAuth = auth
	inv.ParentPreUUID = userdata.FilesToAuths[hex.EncodeToString(userlib.Hash([]byte(filename)))]
	inv.ParentKey = userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))]

	// Marshal invitation
	inv_bytes, err := json.Marshal(inv)
	if err != nil {
		return uuid.Nil, errors.New("Could not marshal invitation.")
	}

	// Upload invitation
	userlib.DatastoreSet(invitationPtr, inv_bytes)

	return invitationPtr, nil
}

func (userdata *User) AcceptInvitation(senderUsername string, invitationPtr uuid.UUID, filename string) error {
	// Download invitation
	inv_bytes, ok := userlib.DatastoreGet(invitationPtr)
	if !ok {
		return errors.New("Could not access the invitation in datastore.")
	}

	// Unmarshal inivtation
	var inv Invitation
	err := json.Unmarshal(inv_bytes, &inv)
	if err != nil {
		return errors.New("Could not unmarshal the invitation.")
	}

	// Verify sender and recipient
	if hex.EncodeToString(userlib.Hash([]byte(senderUsername))) != inv.SenderHash ||
		hex.EncodeToString(userdata.Username) != inv.RecipientHash {
		return errors.New("The invitation has been compromised.")
	}

	// Check if the file already exists in the user's personal namespace
	_, ok = userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))]
	if ok {
		return errors.New("The user already has a file with the same name in their personal namespace.")
	}

	if inv.ParentAuth.IsRoot {
		// Create a child authorization
		var child_auth Authorization
		child_auth.Key = inv.SK
		child_auth.Username = hex.EncodeToString(userdata.Username)
		child_auth.FileID = inv.FileID
		child_auth.Children = make(map[string]string)
		child_auth.IsRoot = false

		// Create a symmetric key deterministically for the child authorization
		key, err := userlib.HashKDF(inv.ParentKey, userdata.Username)
		if err != nil {
			return errors.New("Could not generate a child key for the recipient.")
		}
		key = key[:16]
		userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))] = key
		userdata.FilesToAuths[hex.EncodeToString(userlib.Hash([]byte(filename)))] = hex.EncodeToString(userdata.Username)[:8] + hex.EncodeToString(userlib.Hash([]byte(filename)))[:8]

		// Marshal child authorization
		child_auth_bytes, err := json.Marshal(child_auth)
		if err != nil {
			return errors.New("Could not marshal child authorization.")
		}

		// Encrypt child authorization
		child_auth_enc := userlib.SymEnc(key, make([]byte, 16), child_auth_bytes)

		// Upload child authorization
		auth_uuid, err := uuid.FromBytes([]byte(hex.EncodeToString(userdata.Username)[:8] + hex.EncodeToString(userlib.Hash([]byte(filename)))[:8]))
		if err != nil {
			return errors.New("Could not generate a valid UUID for the child authorization.")
		}
		userlib.DatastoreSet(auth_uuid, child_auth_enc)

		// Upload child authorization's HMAC
		hmac_child_auth, err := userlib.HMACEval(key, child_auth_enc)
		if err != nil {
			return errors.New("Could not compute a valid HMAC for the child authorization.")
		}
		hmac_child_uuid, err := uuid.FromBytes(
			userlib.Hash([]byte(hex.EncodeToString(userdata.Username)[:8] + hex.EncodeToString(userlib.Hash([]byte(filename)))[:8]))[:16])
		if err != nil {
			return errors.New("Could not generate a valid UUID for the child authorization's HMAC.")
		}
		userlib.DatastoreSet(hmac_child_uuid, hmac_child_auth)

		// Update parent authorization
		inv.ParentAuth.Children[hex.EncodeToString(userdata.Username)] = hex.EncodeToString(userdata.Username)[:8] + hex.EncodeToString(userlib.Hash([]byte(filename)))[:8]

		// Marshal parent authorization
		parent_auth_bytes, err := json.Marshal(inv.ParentAuth)
		if err != nil {
			return errors.New("Could not marshal parent authorization.")
		}

		// Encrypt parent authorization
		parent_auth_enc := userlib.SymEnc(inv.ParentKey, make([]byte, 16), parent_auth_bytes)

		// Upload parent authorization
		parent_auth_uuid, err := uuid.FromBytes([]byte(inv.ParentPreUUID)[:16])
		if err != nil {
			return errors.New("Could not generate a valid UUID for the parent authorization.")
		}
		userlib.DatastoreSet(parent_auth_uuid, parent_auth_enc)

		// Update parent authorization's HMAC
		hmac_parent_auth, err := userlib.HMACEval(inv.ParentKey, parent_auth_enc)
		if err != nil {
			return errors.New("Could not compute a valid HMAC for the parent authorization.")
		}
		parent_auth_hmac_uuid, err := uuid.FromBytes(userlib.Hash([]byte(inv.ParentPreUUID))[:16])
		if err != nil {
			return errors.New("Could not generate a valid UUID for the parent authorization's HMAC.")
		}
		userlib.DatastoreSet(parent_auth_hmac_uuid, hmac_parent_auth)
	} else {
		userdata.FilesToAuths[hex.EncodeToString(userlib.Hash([]byte(filename)))] = inv.ParentPreUUID
		userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))] = inv.ParentKey
	}

	return nil
}

func (userdata *User) RevokeAccess(filename string, recipientUsername string) error {
	auth_uuid, err := uuid.FromBytes([]byte(userdata.FilesToAuths[hex.EncodeToString(userlib.Hash([]byte(filename)))])[:16])
	if err != nil {
		return errors.New("Could not generate a valid UUID for the the file's authorization.")
	}

	// Download authorization
	auth_data, ok := userlib.DatastoreGet(auth_uuid)
	if !ok {
		return errors.New("Could not download authorization.")
	}

	// Decrypt authorization
	auth_marshal := userlib.SymDec(userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))], auth_data)

	// Verify authorization HMAC
	hmac_id, err := uuid.FromBytes(userlib.Hash([]byte(userdata.FilesToAuths[hex.EncodeToString(userlib.Hash([]byte(filename)))]))[:16])
	if err != nil {
		return errors.New("Could not find a valid authorization HMAC UUID for the given filename.")
	}
	hmac_then, ok := userlib.DatastoreGet(hmac_id)
	if !ok {
		return errors.New("Could not download the authorization's HMAC.")
	}
	key := userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))]
	hmac_now, err := userlib.HMACEval(key, auth_data)
	if err != nil {
		return errors.New("Could not generate a HMAC for the given user and file's authorization.")
	}
	if !userlib.HMACEqual(hmac_now, hmac_then) {
		return errors.New("The authorization for this user and file has been compromised.")
	}

	// Unmarshal authorization
	var auth Authorization
	err = json.Unmarshal(auth_marshal, &auth)
	if err != nil {
		return errors.New("Could not unmarshal the authorization.")
	}

	// Download file
	file_uuid := auth.FileID
	file_data, ok := userlib.DatastoreGet(file_uuid)
	if !ok {
		return errors.New("Could not download file.")
	}

	// Decrypt file
	file_dec := userlib.SymDec(auth.Key, file_data)

	// Revoke user
	err = auth.RevokeUser(userdata, filename, hex.EncodeToString(userlib.Hash([]byte(recipientUsername))))
	if err != nil {
		return err
	}

	// Remarshal authorization
	auth_bytes, err := json.Marshal(auth)
	if err != nil {
		return errors.New("Could not marshal authorization.")
	}

	// Re-encrypt authorization
	auth_enc := userlib.SymEnc(userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))], make([]byte, 16), auth_bytes)

	// Upload authorization
	userlib.DatastoreSet(auth_uuid, auth_enc)

	// Update authorization HMAC
	key = userdata.FilesToKeys[hex.EncodeToString(userlib.Hash([]byte(filename)))]
	hmac_now, err = userlib.HMACEval(key, auth_enc)
	if err != nil {
		return errors.New("Could not generate a HMAC for the given user and file's authorization (2).")
	}
	userlib.DatastoreSet(hmac_id, hmac_now)

	// Re-encrypt file
	file_enc := userlib.SymEnc(auth.Key, make([]byte, 16), file_dec)

	// Re-upload file
	userlib.DatastoreSet(auth.FileID, file_enc)

	return nil
}

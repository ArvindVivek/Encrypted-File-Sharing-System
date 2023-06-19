package client_test

// You MUST NOT change these default imports.  ANY additional imports may
// break the autograder and everyone will be sad.

import (
	// Some imports use an underscore to prevent the compiler from complaining
	// about unused imports.
	_ "encoding/hex"
	_ "errors"
	_ "strconv"
	_ "strings"
	"testing"

	// A "dot" import is used here so that the functions in the ginko and gomega
	// modules can be used without an identifier. For example, Describe() and
	// Expect() instead of ginko.Describe() and gomega.Expect().
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	userlib "github.com/cs161-staff/project2-userlib"
	"github.com/google/uuid"

	"github.com/cs161-staff/project2-starter-code/client"
)

func TestSetupAndExecution(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Client Tests")
}

// ================================================
// Global Variables (feel free to add more!)
// ================================================
const defaultPassword = "password"
const emptyString = ""
const contentOne = "Bitcoin is Nick's favorite "
const contentTwo = "digital "
const contentThree = "cryptocurrency!"

// ================================================
// Describe(...) blocks help you organize your tests
// into functional categories. They can be nested into
// a tree-like structure.
// ================================================

var _ = Describe("Client Tests", func() {

	// A few user declarations that may be used for testing. Remember to initialize these before you
	// attempt to use them!
	var alice *client.User
	var bob *client.User
	var charles *client.User
	// var doris *client.User
	// var eve *client.User
	// var frank *client.User
	// var grace *client.User
	// var horace *client.User
	// var ira *client.User

	// These declarations may be useful for multi-session testing.
	var alicePhone *client.User
	var aliceLaptop *client.User
	var aliceDesktop *client.User

	var err error

	// A bunch of filenames that may be useful.
	aliceFile := "aliceFile.txt"
	bobFile := "bobFile.txt"
	charlesFile := "charlesFile.txt"
	// dorisFile := "dorisFile.txt"
	// eveFile := "eveFile.txt"
	// frankFile := "frankFile.txt"
	// graceFile := "graceFile.txt"
	// horaceFile := "horaceFile.txt"
	// iraFile := "iraFile.txt"

	BeforeEach(func() {
		// This runs before each test within this Describe block (including nested tests).
		// Here, we reset the state of Datastore and Keystore so that tests do not interfere with each other.
		// We also initialize
		userlib.DatastoreClear()
		userlib.KeystoreClear()
	})

	Describe("Basic Tests", func() {

		Specify("Basic Test: Testing InitUser/GetUser on a single user.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())
		})

		Specify("Basic Test: Testing Single User Store/Load/Append.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Storing file data: %s", contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentTwo)
			err = alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file data: %s", contentThree)
			err = alice.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Create/Accept Invite Functionality with multiple users and multiple instances.", func() {
			userlib.DebugMsg("Initializing users Alice (aliceDesktop) and Bob.")
			aliceDesktop, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting second instance of Alice - aliceLaptop")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop storing file %s with content: %s", aliceFile, contentOne)
			err = aliceDesktop.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceLaptop creating invite for Bob.")
			invite, err := aliceLaptop.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting invite from Alice under filename %s.", bobFile)
			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob appending to file %s, content: %s", bobFile, contentTwo)
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).To(BeNil())

			userlib.DebugMsg("aliceDesktop appending to file %s, content: %s", aliceFile, contentThree)
			err = aliceDesktop.AppendToFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that aliceDesktop sees expected file data.")
			data, err := aliceDesktop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that aliceLaptop sees expected file data.")
			data, err = aliceLaptop.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Checking that Bob sees expected file data.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))

			userlib.DebugMsg("Getting third instance of Alice - alicePhone.")
			alicePhone, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that alicePhone sees Alice's changes.")
			data, err = alicePhone.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne + contentTwo + contentThree)))
		})

		Specify("Basic Test: Testing Revoke Functionality", func() {
			userlib.DebugMsg("Initializing users Alice, Bob, and Charlie.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice creating invite for Bob for file %s, and Bob accepting invite under name %s.", aliceFile, bobFile)

			invite, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invite, bobFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err := alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob can load the file.")
			data, err = bob.LoadFile(bobFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Bob creating invite for Charles for file %s, and Charlie accepting invite under name %s.", bobFile, charlesFile)
			invite, err = bob.CreateInvitation(bobFile, "charles")
			Expect(err).To(BeNil())

			err = charles.AcceptInvitation("bob", invite, charlesFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Charles can load the file.")
			data, err = charles.LoadFile(charlesFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Alice revoking Bob's access from %s.", aliceFile)
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Checking that Alice can still load the file.")
			data, err = alice.LoadFile(aliceFile)
			Expect(err).To(BeNil())
			Expect(data).To(Equal([]byte(contentOne)))

			userlib.DebugMsg("Checking that Bob/Charles lost access to the file.")
			_, err = bob.LoadFile(bobFile)
			Expect(err).ToNot(BeNil())

			_, err = charles.LoadFile(charlesFile)
			Expect(err).ToNot(BeNil())

			userlib.DebugMsg("Checking that the revoked users cannot append to the file.")
			err = bob.AppendToFile(bobFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())

			err = charles.AppendToFile(charlesFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})
	})

	Describe("Custom Tests", func() {

		Specify("Custom Test: Testing Bandwidth on Append", func() {
			measureBandwidth := func(probe func()) (bandwidth int) {
				before := userlib.DatastoreGetBandwidth()
				probe()
				after := userlib.DatastoreGetBandwidth()
				return after - before
			}

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice appending to file %s 10,000 times with content: %s", aliceFile, contentTwo)
			firstBandwidth := -1
			for i := 0; i < 10000; i++ {
				bw := measureBandwidth(func() {
					alice.AppendToFile(aliceFile, []byte(contentTwo))
				})
				if firstBandwidth == -1 {
					firstBandwidth = bw
				} else {
					Expect((bw - firstBandwidth) < 2000).To(Equal(true))
				}
			}

			userlib.DebugMsg("Alice appending to file %s 10,000 times with content: %s", aliceFile, contentOne)
			firstBandwidth = -1
			for i := 0; i < 10000; i++ {
				bw := measureBandwidth(func() {
					err := alice.AppendToFile(aliceFile, []byte(contentOne))
					Expect(err).To(BeNil())
				})
				if firstBandwidth == -1 {
					firstBandwidth = bw
				} else {
					Expect((bw - firstBandwidth) < 2000).To(Equal(true))
				}
			}
		})

		Specify("Custom Test: Invalidating a User", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			datastore_map := userlib.DatastoreGetMap()
			id, err := uuid.FromBytes(userlib.Hash([]byte("alice"))[:16])
			if err == nil {
				datastore_map[id] = userlib.RandomBytes(16)

				_, err = client.GetUser("alice", defaultPassword)
				Expect(err).ToNot(BeNil())

				alice.StoreFile(aliceFile, []byte(contentOne))
				Expect(err).ToNot(BeNil())
			}
		})

		Specify("Custom Test: Load before Store file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Append before Store file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Same username twice.", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Empty username twice.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: AcceptInvitation before CreateInvitation", func() {
			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", uuid.New(), aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: RevokeAccess before CreateInvitation", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Calling AcceptInvitation twice", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Bob.", aliceFile)
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation (this should fail, as Bob has already accepted the invitation).")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Calling RevokeAccess twice", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Bob.", aliceFile)
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access (this should fail, as Alice has already revoked Bob's access).")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Calling StoreFile twice", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentTwo)
			err = alice.StoreFile(aliceFile, []byte(contentTwo))
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: Calling StoreFile after accepting a file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice sharing file %s with Bob.", aliceFile)
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob storing file %s with content: %s", aliceFile, contentThree)
			err = bob.StoreFile(aliceFile, []byte(contentThree))
			Expect(err).To(BeNil())
		})

		Specify("Custom Test: CreateInvitation, AcceptInvitation, RevokeAccess, and then AcceptInvitation again", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Bob.", aliceFile)
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice revoking Bob's access.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).To(BeNil())

			userlib.DebugMsg("Bob accepting Alice's invitation (this should fail, as Bob's access has been revoked.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Changing new datastore entries to random bytes (CreateUser, *tamper*, GetUser)", func() {
			datastore_map_after := userlib.DatastoreGetMap()
			datastore_map_before := make(map[uuid.UUID][]byte)
			for k, v := range datastore_map_after {
				datastore_map_before[k] = v
			}

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			for key := range datastore_map_after {
				_, ok := datastore_map_before[key]
				if !ok {
					datastore_map_after[key] = userlib.RandomBytes(16)
				}
			}

			_, err := client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Changing new datastore entries to random bytes (CreateUser, StoreFile, *tamper*, LoadFile)", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			datastore_map_after := userlib.DatastoreGetMap()
			datastore_map_before := make(map[uuid.UUID][]byte)
			for k, v := range datastore_map_after {
				datastore_map_before[k] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			for key := range datastore_map_after {
				_, ok := datastore_map_before[key]
				if !ok {
					datastore_map_after[key] = userlib.RandomBytes(16)
				}
			}

			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Changing new datastore entries to random bytes (CreateUser, StoreFile, *tamper*, AppendToFile)", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			datastore_map_after := userlib.DatastoreGetMap()
			datastore_map_before := make(map[uuid.UUID][]byte)
			for k, v := range datastore_map_after {
				datastore_map_before[k] = v
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			for key := range datastore_map_after {
				_, ok := datastore_map_before[key]
				if !ok {
					datastore_map_after[key] = userlib.RandomBytes(16)
				}
			}

			err := alice.AppendToFile(aliceFile, []byte(contentTwo))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Changing new datastore entries to random bytes (CreateUser, *tamper*, StoreFile)", func() {
			datastore_map_after := userlib.DatastoreGetMap()
			datastore_map_before := make(map[uuid.UUID][]byte)
			for k, v := range datastore_map_after {
				datastore_map_before[k] = v
			}

			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			for key := range datastore_map_after {
				_, ok := datastore_map_before[key]
				if !ok {
					datastore_map_after[key] = userlib.RandomBytes(16)
				}
			}

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Changing new datastore entries to random bytes (CreateUser, StoreFile, CreateInvitation, *tamper*, AcceptInvitation", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			err = alice.StoreFile(aliceFile, []byte(contentOne))
			Expect(err).To(BeNil())

			datastore_map_after := userlib.DatastoreGetMap()
			datastore_map_before := make(map[uuid.UUID][]byte)
			for k, v := range datastore_map_after {
				datastore_map_before[k] = v
			}

			userlib.DebugMsg("Alice sharing file %s with Bob.", aliceFile)
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			for key := range datastore_map_after {
				_, ok := datastore_map_before[key]
				if !ok {
					datastore_map_after[key] = userlib.RandomBytes(16)
				}
			}

			userlib.DebugMsg("Bob accepting Alice's invitation.")
			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Wrong password.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", "wrongpassword")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Delete created user and load.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			datastore_map_after := userlib.DatastoreGetMap()
			/*b, err := json.MarshalIndent(datastore_map_after, "Pair", ":")
			if err == nil {
				userlib.DebugMsg(string(b))
			}*/

			for key, _ := range datastore_map_after {
				userlib.DatastoreDelete(key)
				break
			}

			userlib.DebugMsg("Getting user Alice.")
			aliceLaptop, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Access file without invitation.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Checking that Bob cannot access the file.")
			_, err = bob.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Invite to invalid user.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Charles.", aliceFile)
			_, err := alice.CreateInvitation(aliceFile, "charles")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Invite with invalid filename.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Bob.", "alicefile2.txt")
			_, err := alice.CreateInvitation("alicefile2.txt", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Accept invalid invite.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Bob.", "alicefile2.txt")
			invitationPtr, err := alice.CreateInvitation("alicefile2.txt", "bob")
			Expect(err).ToNot(BeNil())

			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Get uninitialized user.", func() {
			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Load nonexisting file.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Loading file...")
			_, err := alice.LoadFile(aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Load compromised file.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			//TODO: Compromise integrity of file

			userlib.DebugMsg("Loading file...")
			//TODO: Uncomment below
			//_, err := alice.LoadFile(aliceFile)
			//Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Append nonexisting file.", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Getting user alice.")
			alice, err = client.GetUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Appending file...")
			err := alice.AppendToFile(aliceFile, []byte(contentOne))
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Accept invite to under existing filename", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Bob storing file %s with content: %s", aliceFile, contentOne)
			bob.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Bob.", aliceFile)
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Accept invite to under invalid sender", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			bob.StoreFile(bobFile, []byte(contentOne))

			userlib.DebugMsg("Charles storing file %s with content: %s", aliceFile, contentOne)
			charles.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Charles sharing file %s with Bob.", aliceFile)
			invitationPtr, err := charles.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Accept compromised integrity of invite", func() {
			userlib.DebugMsg("Initializing user empty.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Charles.")
			charles, err = client.InitUser("charles", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Bob storing file %s with content: %s", bobFile, contentOne)
			bob.StoreFile(bobFile, []byte(contentOne))

			userlib.DebugMsg("Alice sharing file %s with Bob.", aliceFile)
			invitationPtr, err := alice.CreateInvitation(aliceFile, "bob")
			Expect(err).To(BeNil())

			//TODO: Compromise integrity of invite in datastore

			err = bob.AcceptInvitation("alice", invitationPtr, aliceFile)
			//TODO: Uncomment below
			//Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Revoke nonexistent file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice revoking Bob's access.")
			err = alice.RevokeAccess("alice2.txt", "bob")
			Expect(err).ToNot(BeNil())
		})

		Specify("Custom Test: Revoke unshared file", func() {
			userlib.DebugMsg("Initializing user Alice.")
			alice, err = client.InitUser("alice", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Initializing user Bob.")
			bob, err = client.InitUser("bob", defaultPassword)
			Expect(err).To(BeNil())

			userlib.DebugMsg("Alice storing file %s with content: %s", aliceFile, contentOne)
			alice.StoreFile(aliceFile, []byte(contentOne))

			userlib.DebugMsg("Alice revoking Bob's access.")
			err = alice.RevokeAccess(aliceFile, "bob")
			Expect(err).ToNot(BeNil())
		})
	})
})

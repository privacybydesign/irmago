package sqlcipher

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// ---------------------------------------------------------------------------
// Test-only models — not exported, only used in this file.
// ---------------------------------------------------------------------------

type author struct {
	ID        uint      `gorm:"primaryKey;autoIncrement"`
	Name      string    `gorm:"type:text;not null"`
	Bio       string    `gorm:"type:text"`
	Books     []book    `gorm:"foreignKey:AuthorID;constraint:OnDelete:CASCADE"`
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

type book struct {
	ID          uint       `gorm:"primaryKey;autoIncrement"`
	AuthorID    uint       `gorm:"not null;index"`
	Title       string     `gorm:"type:text;not null"`
	ISBN        string     `gorm:"type:text;uniqueIndex"`
	CoverImage  []byte     `gorm:"type:blob"`
	PublishedAt *time.Time `gorm:"type:datetime"`
	Tags        []tag      `gorm:"many2many:book_tags"`
	Reviews     []review   `gorm:"foreignKey:BookID;constraint:OnDelete:CASCADE"`
}

type tag struct {
	ID    uint   `gorm:"primaryKey;autoIncrement"`
	Label string `gorm:"type:text;not null;uniqueIndex"`
	Books []book `gorm:"many2many:book_tags"`
}

type review struct {
	ID     uint    `gorm:"primaryKey;autoIncrement"`
	BookID uint    `gorm:"not null;index"`
	Rating float64 `gorm:"not null"`
	Body   string  `gorm:"type:text"`
}

// openRelationDB creates an encrypted in-memory DB with the relation models migrated.
func openRelationDB(t *testing.T) *gorm.DB {
	t.Helper()
	key := []byte("rel-test-key")
	db, err := gorm.Open(Dialector{Connector: NewConnector(":memory:", key)}, &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&author{}, &book{}, &tag{}, &review{}))
	return db
}

// --- HasMany ---

func TestRelation_HasMany_CreateWithChildren(t *testing.T) {
	db := openRelationDB(t)

	a := &author{
		Name: "Alice",
		Books: []book{
			{Title: "Go Internals", ISBN: "111"},
			{Title: "Concurrency Patterns", ISBN: "222"},
		},
	}
	require.NoError(t, db.Create(a).Error)
	assert.NotZero(t, a.ID)
	assert.NotZero(t, a.Books[0].ID)
	assert.NotZero(t, a.Books[1].ID)

	// Read back with Preload.
	var got author
	require.NoError(t, db.Preload("Books").First(&got, a.ID).Error)
	assert.Len(t, got.Books, 2)
	assert.Equal(t, a.ID, got.Books[0].AuthorID)
}

func TestRelation_HasMany_CascadeDelete(t *testing.T) {
	db := openRelationDB(t)

	a := &author{
		Name:  "Bob",
		Books: []book{{Title: "Deleted Book", ISBN: "del-1"}},
	}
	require.NoError(t, db.Create(a).Error)

	require.NoError(t, db.Delete(&author{}, a.ID).Error)

	var bookCount int64
	db.Model(&book{}).Where("author_id = ?", a.ID).Count(&bookCount)
	assert.Equal(t, int64(0), bookCount, "books should be cascade-deleted with author")
}

// --- ManyToMany ---

func TestRelation_ManyToMany_AssociateAndQuery(t *testing.T) {
	db := openRelationDB(t)

	tags := []tag{{Label: "go"}, {Label: "database"}, {Label: "testing"}}
	for i := range tags {
		require.NoError(t, db.Create(&tags[i]).Error)
	}

	a := &author{Name: "Carol"}
	require.NoError(t, db.Create(a).Error)

	b := &book{AuthorID: a.ID, Title: "Testing with SQLite", ISBN: "m2m-1", Tags: []tag{tags[0], tags[2]}}
	require.NoError(t, db.Create(b).Error)

	// Read back book with tags.
	var got book
	require.NoError(t, db.Preload("Tags").First(&got, b.ID).Error)
	assert.Len(t, got.Tags, 2)

	labels := []string{got.Tags[0].Label, got.Tags[1].Label}
	assert.Contains(t, labels, "go")
	assert.Contains(t, labels, "testing")
}

func TestRelation_ManyToMany_SharedTagBetweenBooks(t *testing.T) {
	db := openRelationDB(t)

	goTag := &tag{Label: "go"}
	require.NoError(t, db.Create(goTag).Error)

	a := &author{Name: "Dave"}
	require.NoError(t, db.Create(a).Error)

	b1 := &book{AuthorID: a.ID, Title: "Book A", ISBN: "shared-1", Tags: []tag{*goTag}}
	b2 := &book{AuthorID: a.ID, Title: "Book B", ISBN: "shared-2", Tags: []tag{*goTag}}
	require.NoError(t, db.Create(b1).Error)
	require.NoError(t, db.Create(b2).Error)

	// Query the tag and preload its books.
	var got tag
	require.NoError(t, db.Preload("Books").First(&got, goTag.ID).Error)
	assert.Len(t, got.Books, 2, "tag should be shared by two books")
}

func TestRelation_ManyToMany_RemoveAssociation(t *testing.T) {
	db := openRelationDB(t)

	tags := []tag{{Label: "remove-a"}, {Label: "remove-b"}}
	for i := range tags {
		require.NoError(t, db.Create(&tags[i]).Error)
	}

	a := &author{Name: "Eve"}
	require.NoError(t, db.Create(a).Error)

	b := &book{AuthorID: a.ID, Title: "Pruned", ISBN: "prune-1", Tags: tags}
	require.NoError(t, db.Create(b).Error)

	// Remove one tag from the association.
	require.NoError(t, db.Model(b).Association("Tags").Delete(&tags[0]))

	var got book
	require.NoError(t, db.Preload("Tags").First(&got, b.ID).Error)
	assert.Len(t, got.Tags, 1)
	assert.Equal(t, "remove-b", got.Tags[0].Label)

	// The tag itself must still exist.
	require.NoError(t, db.First(&tag{}, tags[0].ID).Error)
}

// --- Nested preload (HasMany -> HasMany) ---

func TestRelation_NestedPreload(t *testing.T) {
	db := openRelationDB(t)

	a := &author{
		Name: "Frank",
		Books: []book{
			{
				Title: "Nested Book",
				ISBN:  "nested-1",
				Reviews: []review{
					{Rating: 4.5, Body: "Great"},
					{Rating: 3.0, Body: "OK"},
				},
			},
		},
	}
	require.NoError(t, db.Create(a).Error)

	var got author
	require.NoError(t, db.Preload("Books.Reviews").First(&got, a.ID).Error)
	require.Len(t, got.Books, 1)
	assert.Len(t, got.Books[0].Reviews, 2)
}

// --- Multi-level cascade ---

func TestRelation_MultiLevelCascadeDelete(t *testing.T) {
	db := openRelationDB(t)

	a := &author{
		Name: "Grace",
		Books: []book{
			{
				Title:   "Cascading Book",
				ISBN:    "cascade-1",
				Reviews: []review{{Rating: 5.0, Body: "Excellent"}},
			},
		},
	}
	require.NoError(t, db.Create(a).Error)
	bookID := a.Books[0].ID

	// Delete author — books and their reviews must be gone.
	require.NoError(t, db.Delete(&author{}, a.ID).Error)

	var bookCount, reviewCount int64
	db.Model(&book{}).Where("id = ?", bookID).Count(&bookCount)
	db.Model(&review{}).Where("book_id = ?", bookID).Count(&reviewCount)
	assert.Equal(t, int64(0), bookCount)
	assert.Equal(t, int64(0), reviewCount, "reviews should be transitively cascade-deleted")
}

// --- Nullable columns and edge-cases ---

func TestRelation_NullableFieldsRoundTrip(t *testing.T) {
	db := openRelationDB(t)

	a := &author{Name: "Hank"}
	require.NoError(t, db.Create(a).Error)

	// Book with nil PublishedAt and nil CoverImage.
	b := &book{AuthorID: a.ID, Title: "Draft", ISBN: "null-1"}
	require.NoError(t, db.Create(b).Error)

	var got book
	require.NoError(t, db.First(&got, b.ID).Error)
	assert.Nil(t, got.PublishedAt, "nullable datetime should be nil")
	assert.Empty(t, got.CoverImage, "nullable blob should be empty")

	// Update to non-nil values.
	now := time.Now().Truncate(time.Second)
	cover := []byte{0x89, 0x50, 0x4E, 0x47} // PNG magic bytes
	require.NoError(t, db.Model(&got).Updates(map[string]any{
		"published_at": now,
		"cover_image":  cover,
	}).Error)

	var updated book
	require.NoError(t, db.First(&updated, b.ID).Error)
	require.NotNil(t, updated.PublishedAt)
	assert.Equal(t, now.UTC(), updated.PublishedAt.UTC())
	assert.Equal(t, cover, updated.CoverImage)
}

// --- Batch insert ---

func TestRelation_BatchInsertMultipleAuthorsWithBooks(t *testing.T) {
	db := openRelationDB(t)

	// Insert each author individually — GORM's batch insert of a slice with
	// nested associations can violate FK constraints in SQLite because it may
	// attempt to insert children before parents.
	type testCase struct {
		name      string
		bookCount int
	}
	cases := []testCase{
		{"Author-1", 1},
		{"Author-2", 2},
		{"Author-3", 1},
	}

	isbn := 0
	for _, tc := range cases {
		books := make([]book, tc.bookCount)
		for i := range books {
			isbn++
			books[i] = book{Title: fmt.Sprintf("%s-B%d", tc.name, i+1), ISBN: fmt.Sprintf("batch-%d", isbn)}
		}
		require.NoError(t, db.Create(&author{Name: tc.name, Books: books}).Error)
	}

	var totalBooks int64
	db.Model(&book{}).Count(&totalBooks)
	assert.Equal(t, int64(4), totalBooks)

	// Verify each author got the right number of books.
	var authors []author
	require.NoError(t, db.Preload("Books").Find(&authors).Error)
	for i, a := range authors {
		assert.Len(t, a.Books, cases[i].bookCount)
	}
}

// --- Conditional queries with relations ---

func TestRelation_QueryWithJoinsAndConditions(t *testing.T) {
	db := openRelationDB(t)

	a := &author{Name: "Iris"}
	require.NoError(t, db.Create(a).Error)

	low := &book{AuthorID: a.ID, Title: "Low Rated", ISBN: "cond-1",
		Reviews: []review{{Rating: 1.0}}}
	high := &book{AuthorID: a.ID, Title: "High Rated", ISBN: "cond-2",
		Reviews: []review{{Rating: 5.0}, {Rating: 4.0}}}
	require.NoError(t, db.Create(low).Error)
	require.NoError(t, db.Create(high).Error)

	// Find books that have at least one review with rating >= 4.
	var highRated []book
	require.NoError(t, db.
		Joins("JOIN reviews ON reviews.book_id = books.id").
		Where("reviews.rating >= ?", 4.0).
		Distinct().
		Find(&highRated).Error)
	assert.Len(t, highRated, 1)
	assert.Equal(t, "High Rated", highRated[0].Title)
}

// --- Replace associations ---

func TestRelation_ManyToMany_ReplaceAssociations(t *testing.T) {
	db := openRelationDB(t)

	original := []tag{{Label: "old-a"}, {Label: "old-b"}}
	replacement := []tag{{Label: "new-x"}}
	for i := range original {
		require.NoError(t, db.Create(&original[i]).Error)
	}
	for i := range replacement {
		require.NoError(t, db.Create(&replacement[i]).Error)
	}

	a := &author{Name: "Jack"}
	require.NoError(t, db.Create(a).Error)
	b := &book{AuthorID: a.ID, Title: "Retagged", ISBN: "replace-1", Tags: original}
	require.NoError(t, db.Create(b).Error)

	// Replace all tags.
	require.NoError(t, db.Model(b).Association("Tags").Replace(replacement))

	var got book
	require.NoError(t, db.Preload("Tags").First(&got, b.ID).Error)
	require.Len(t, got.Tags, 1)
	assert.Equal(t, "new-x", got.Tags[0].Label)

	// Original tags must still exist as standalone rows.
	for _, tg := range original {
		require.NoError(t, db.First(&tag{}, tg.ID).Error,
			fmt.Sprintf("tag %q should still exist after un-linking", tg.Label))
	}
}

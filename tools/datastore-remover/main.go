package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"cloud.google.com/go/datastore"
	"github.com/remeh/sizedwaitgroup"
	"google.golang.org/api/iterator"
)

var (
	kind       = flag.String("kind", "", "kind to delete")
	projectID  = flag.String("project_id", "", "the gcp project ID")
	batchSize  = flag.Int("batch_size", 500, "batch size for deletions")
	waitTimeMS = flag.Int("wait_ms", 500, "wait time in between batch deletions")
	total      atomic.Int64
)

func main() {
	flag.Parse()
	if *kind == "" || *projectID == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	ctx := context.Background()

	scanner := bufio.NewScanner(os.Stdin)
	fmt.Printf("Deleting kind: %s, in project: %s\nEnter yes to confirm: \n", *kind, *projectID)
	scanner.Scan()
	if scanner.Text() != "yes" {
		fmt.Println("Not yes entered, exiting")
		os.Exit(1)
	}

	client, _ := datastore.NewClient(ctx, *projectID)
	var wg = sizedwaitgroup.New(16)
	// Invert for loop nesting (this spreads the delete out more evenly)
	for ii := 0; ii < 16; ii++ {
		for i := 0; i < 16; i++ {
			iStr := strconv.FormatInt(int64(i), 16)
			iiStr := strconv.FormatInt(int64(ii), 16)
			iiStrEnd := strconv.FormatInt(int64(ii+1), 16)
			i := i
			ii := ii
			wg.Add()
			go func() {
				defer wg.Done()
				query := datastore.NewQuery(*kind).Order("commit").FilterField("commit", ">", iStr+iiStr).KeysOnly()
				if i != 15 && ii != 15 {
					query = query.FilterField("commit", "<", iStr+iiStrEnd)
				}
				it := client.Run(ctx, query)

				var batch []*datastore.Key
				for {
					key, err := it.Next(nil)
					if err == iterator.Done {
						break
					}
					if err != nil {
						log.Fatalf("%v", err)
					}
					batch = append(batch, key)

					if len(batch) >= *batchSize {
						deleteBatch(ctx, client, batch)
						batch = nil
					}
				}

				if len(batch) > 0 {
					deleteBatch(ctx, client, batch)
				}
			}()
		}
	}
	wg.Wait()
}

func deleteBatch(ctx context.Context, client *datastore.Client, keys []*datastore.Key) {
	err := client.DeleteMulti(ctx, keys)
	if err != nil {
		log.Fatalf("%v", err)
	}
	total.Add(int64(len(keys)))
	localTotal := int(total.Load())
	if localTotal%(*batchSize*10) == 0 {
		log.Printf("Deleted %d.\n", localTotal)
	}
	time.Sleep(time.Duration(*waitTimeMS) * time.Millisecond)
}

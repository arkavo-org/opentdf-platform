package integration

import (
	"context"
	"log/slog"
	"strings"

	"github.com/opentdf/opentdf-v2-poc/internal/db"
)

type DBInterface struct {
	Client *db.Client
	schema string
}

func NewDBInterface(schema string) DBInterface {
	config := Config.DB
	config.Schema = schema
	c, err := db.NewClient(config)
	if err != nil {
		slog.Error("issue creating database client", slog.String("error", err.Error()))
		panic(err)
	}
	return DBInterface{
		Client: c,
		schema: schema,
	}
}

func (d *DBInterface) StringArrayWrap(values []string) string {
	// if len(values) == 0 {
	// 	return "null"
	// }
	var vs []string
	for _, v := range values {
		vs = append(vs, d.StringWrap(v))
	}
	return "ARRAY [" + strings.Join(vs, ",") + "]"
}

func (d *DBInterface) UUIDArrayWrap(v []string) string {
	return "(" + d.StringArrayWrap(v) + ")" + "::uuid[]"
}

func (d *DBInterface) StringWrap(v string) string {
	return "'" + v + "'"
}

func (d *DBInterface) UUIDWrap(v string) string {
	return "(" + d.StringWrap(v) + ")" + "::uuid"
}

func (d *DBInterface) TableName(v string) string {
	return d.schema + "." + v
}

func (d *DBInterface) ExecInsert(table string, columns []string, values ...[]string) (int64, error) {
	sql := "INSERT INTO " + d.TableName(table) +
		" (" + strings.Join(columns, ",") + ")" +
		" VALUES "
	for i, v := range values {
		if i > 0 {
			sql += ","
		}
		sql += " (" + strings.Join(v, ",") + ")"
	}
	pconn, err := d.Client.Exec(context.Background(), sql)
	if err != nil {
		return 0, err
	}
	return pconn.RowsAffected(), err
}

func (d *DBInterface) DropSchema() error {
	sql := "DROP SCHEMA IF EXISTS " + d.schema + " CASCADE"
	_, err := d.Client.Exec(context.Background(), sql)
	if err != nil {
		return err
	}
	return nil
}
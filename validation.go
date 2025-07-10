package zensegur

import (
	"errors"
	"reflect"
	"strings"
)

// Validação automática usando tags
type Validator struct {
	rules map[string]func(interface{}) error
}

func NewValidator() *Validator {
	return &Validator{
		rules: make(map[string]func(interface{}) error),
	}
}

func (v *Validator) AddRule(tag string, fn func(interface{}) error) {
	v.rules[tag] = fn
}

func (v *Validator) Validate(data interface{}) error {
	val := reflect.ValueOf(data)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	
	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldType := typ.Field(i)
		
		tag := fieldType.Tag.Get("validate")
		if tag == "" {
			continue
		}
		
		rules := strings.Split(tag, ",")
		for _, rule := range rules {
			if fn, exists := v.rules[rule]; exists {
				if err := fn(field.Interface()); err != nil {
					return errors.New(fieldType.Name + ": " + err.Error())
				}
			}
		}
	}
	return nil
}

// Validações comuns
func init() {
	defaultValidator := NewValidator()
	
	defaultValidator.AddRule("required", func(v interface{}) error {
		if v == nil || v == "" {
			return errors.New("field is required")
		}
		return nil
	})
	
	defaultValidator.AddRule("email", func(v interface{}) error {
		str, ok := v.(string)
		if !ok {
			return errors.New("must be string")
		}
		if !strings.Contains(str, "@") {
			return errors.New("invalid email format")
		}
		return nil
	})
}

func (r *Repository) WithValidation(validator *Validator) *Repository {
	// Retorna repository com validação
	return &Repository{
		client:     r.client,
		collection: r.collection,
		ctx:        r.ctx,
	}
}
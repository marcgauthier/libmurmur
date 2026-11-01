// Run from ../MURMUR-SQL; emits fixtures for managed_value_selftest.cc.
package main
import (
	"fmt"
	"math"
	m "github.com/marcgauthier/murmur-sql/murmur"
)
func emit(name string, bytes []byte) { fmt.Printf("%s %x\n",name,bytes) }
func main() {
	values:=[]m.Value{m.NullValue(),m.IntValue(math.MinInt64),m.IntValue(math.MaxInt64),m.RealValue(math.SmallestNonzeroFloat64),m.RealValue(math.Copysign(0,-1)),m.TextValue("<>&\n\u2028\u2029\xff"),m.BlobValue([]byte{0,255})}
	for i,v:=range values { emit(fmt.Sprintf("value%d",i),m.EncodeValue(v)) }
	emit("values",m.EncodeValues(values))
	for i,f:=range []float64{1e5,1e6,1e-4,1e-5,1e20,1e21,math.SmallestNonzeroFloat64,math.MaxFloat64,math.Copysign(0,-1),1.2345678901234567} {
		v,err:=m.RenderListDoc([]m.Value{m.RealValue(f)}); if err!=nil {panic(err)}
		emit(fmt.Sprintf("float%d",i),[]byte(v.S))
	}
	v,err:=m.RenderJsonDoc(map[string]m.Value{"z":m.RealValue(1.5),"<\n\u2028":m.TextValue("<>&\n\u2028\u2029\xff"),"a":m.NullValue()}); if err!=nil {panic(err)}
	emit("json",[]byte(v.S))
}

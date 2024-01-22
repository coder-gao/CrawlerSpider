
const {parse} = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const type = require("@babel/types");
const generator = require("@babel/generator").default;

let jscode =
`
var _0x08=["\x69\x6E\x66\x6F","\u8FD9\u662F\u4E00\u4E2A\u9AD8\u7EA7\u52A0\u5BC6\u7684\u65B9\u5F0F\uFF0C\u52A0\u5BC6\u540E\u4E0D\u80FD\u6062\u590D\uFF0C\u8BF7\u4FDD\u5B58\u597D\u6E90\u7801\u3002","\x61\x64\x69\x6E\x66\x6F","\u7AD9\u957F\u63A5\u624B\u52A8\u52A0\u5BC6\uFF0C\u4FDD\u536B\u4F60\u7684\x20\x6A\x73\u3002"];(function(_0x2841x1,_0x2841x2){_0x2841x1[_0x08[0]]= _0x08[1];_0x2841x2[_0x08[2]]= _0x08[3]})(window,document)
`;

let ast = parse(jscode);



const strTrans =
    {
        StringLiteral(path){
            let {node} = path;
            node.extra = undefined;
        }
    }


// 1. 字符串编码转换， unicode编码需要加上 opts = {jsescOption:{"minimal":true}}
traverse(ast, strTrans);
// 2。自执行函数处理
traverse(ast, {
    CallExpression(path){
        let callee = path.get('callee');
        let arguments = path.get('arguments');

        if(!type.isFunctionExpression(callee) || arguments.length ===0){
            // 实参的长度判断可以写死
            return;
        }

        // 获取形参
        let params = callee.get('params');
        let scope = callee.scope;

        for ( let i =0; i< arguments.length; i++){
            // 遍历实参， 因为形参可能比实参长
            let arg = params[i];
            let {name} = arg.node;

            const binding = scope.getBinding(name);

            if(!binding || binding.constantViolations.length > 0){
                // 形参发生改变，不能被还原
                continue;
            }

            for(refer_path of binding.referencePaths){
                // 字面量可以直接替换
                refer_path.replaceWith(arguments[i]);
            }

            arg.remove();
            arguments[i].remove();
        }

    }
});

// 3. 还原数组对象
traverse(ast, {
    VariableDeclarator(path){
        // 还原数组对象
        const {id, init} = path.node;

        // 非Array或者没有元素， 返回
        if (!type.isArrayExpression(init) || init.elements.length===0) return;

        let elements = init.elements;

        // 获取binding实例
        const binding = path.scope.getBinding(id.name);

        for ( const ref_path of binding.referencePaths){
            // 获取 MemberExpression 父节点
            let member_path = ref_path.findParent(p=>p.isMemberExpression());
            let property = member_path.get('property');

            // 索引值不是 NumericLiteral 类型的不处理
            if(!property.isNumericLiteral()){
                continue;
            }

            // 获取索引值
            let index = property.node.value;

            // 获取索引值对应的节点， 并替换
            let arr_ele = elements[index];
            member_path.replaceWith(arr_ele)
        }
        // 删除数组节点
        path.remove();
    }
});
let {code} = generator(ast,opts = {jsescOption:{"minimal":true}});
console.log(code);

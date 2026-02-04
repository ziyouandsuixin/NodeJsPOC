// @orval/mock 7.19.0 版本 - 命令注入漏洞演示 (仅供安全测试)
// 文件：vulnerable_scalar_generator.js
// 说明：此代码模拟 @orval/mock 7.19.0 中未修复的漏洞逻辑
// 请勿在生产环境使用！

/**
 * 模拟 OpenAPI schema 项目
 */
class SchemaItem {
  constructor(type, constValue, enumValues, pattern) {
    this.type = type;
    this.const = constValue;
    this.enum = enumValues;
    this.pattern = pattern;
    this.name = 'testProperty';
  }
}

/**
 * 模拟 getMockScalar 函数 - 包含漏洞的版本
 * @param {SchemaItem} item - OpenAPI schema 项目
 * @returns {object} mock 定义
 */
function getMockScalarVulnerable(item) {
  const type = item.type;
  let value;
  
  switch (type) {
    case 'number':
    case 'integer': {
      if (item.enum) {
        value = `getEnum([${item.enum.join(', ')}])`;
      } else if ('const' in item) {
        // 🔴 漏洞点1：直接赋值 const 值，无序列化/转义
        value = item.const;
      } else {
        value = 'faker.datatype.number()';
      }
      return { 
        value, 
        enums: item.enum, 
        imports: ['faker'], 
        name: item.name 
      };
    }

    case 'boolean': {
      let value = 'faker.datatype.boolean()';
      if ('const' in item) {
        // 🔴 漏洞点2：直接赋值 const 值，无序列化/转义
        value = item.const;
      }
      return { 
        value, 
        imports: [], 
        name: item.name 
      };
    }

    case 'string': {
      if (item.enum) {
        value = `getEnum([${item.enum.map(v => `'${v}'`).join(', ')}])`;
      } else if (item.pattern) {
        value = `faker.helpers.fromRegExp('${item.pattern}')`;
      } else if ('const' in item) {
        // 🔴 漏洞点3：直接赋值 const 值，无序列化/转义
        value = item.const;
      } else {
        value = 'faker.lorem.word()';
      }
      return { 
        value: value, // 注意：这里应该调用 getNullable，但为了演示简化
        enums: item.enum, 
        name: item.name, 
        imports: ['faker'] 
      };
    }
    
    default:
      return { value: 'unknown', imports: [], name: item.name };
  }
}
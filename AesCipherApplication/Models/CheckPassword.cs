using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace AesCipherApplication.Models
{
    public class CheckPassword : ICloneable
    {
        public bool Latins { get; set; }
        public bool Cyrillics { get; set; }
        public bool Digits { get; set; }
        public bool PunctuationMarks { get; set; }
        public bool ArithmeticOperations { get; set; }
        public int MinLength { get; set; }
        public bool Validate(string input)
        {
            if (input.Length < MinLength)
                return false;
            var checks = new List<string>();
            if (Latins)
            {
                checks.Add(@"A-Za-z");
            }
            if (Cyrillics)
            {
                checks.Add(@"А-Яа-я");
            }
            if (Digits)
            {
                checks.Add(@"\d");
            }
            if (PunctuationMarks)
            {
                checks.Add(@"\.\,\:\?\-""\(\)\;\!");
            }
            if (ArithmeticOperations)
            {
                checks.Add(@"\+\-\*\/");
            }
            if (checks.Count == 0)
            {
                return false;
            }
            else
            {
                var pattern = $"[{string.Join("", checks)}]+";
                var matchKey = Regex.Match(input, pattern);
                return matchKey.Value == input;
            }
        }

        public object Clone()
        {
            return MemberwiseClone();
        }

        public static bool operator !=(CheckPassword n1, CheckPassword n2)
        {
            var props = typeof(CheckPassword).GetProperties();
            foreach(var prop in props)
            {
                var v1 = prop.GetValue(n1).ToString();
                var v2 = prop.GetValue(n2).ToString();
                if (v1 != v2)
                {
                    return true;
                }
            }
            return false;
        }

        public static bool operator ==(CheckPassword n1, CheckPassword n2)
        {
            return !(n1 != n2);
        }
    }
}

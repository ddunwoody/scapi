#include "stdafx.h"

using namespace System;
using namespace System::Text;
using namespace System::Collections::Generic;
using namespace	Microsoft::VisualStudio::TestTools::UnitTesting;

namespace TestProject1
{
	[TestClass]
	public ref class UnitTest1
	{
	public: 
		[TestMethod]
		void TestMethod1()
		{
			cout<<"******rabin*******\n";
			AutoSeededRandomPool rng;
			TrapdoorFunction* rabin = new InvertibleRabinFunction;
			((InvertibleRabinFunction*) rabin)->Initialize(rng, 1024);
			Integer x=10;
			Integer compute = ((TrapdoorFunction *) rabin) -> ApplyFunction(x);
			Integer invert =  ((TrapdoorFunctionInverse *) rabin) -> CalculateInverse(rng, compute);
			cout<<"x: "<<x<<"\n";
			cout<<"compute: "<<compute<<"\n";
			cout<<"invert: "<<invert<<"\n";

		}
	};
}

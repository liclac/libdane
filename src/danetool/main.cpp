/**
 * main.cpp
 * danetool
 * 
 * Copyright 2015 uppfinnarn and Halon Security. All rights reserved.
 */

#include "App.h"

int main(int argc, char **argv)
{
	App app;
	return app.run(std::vector<std::string>(argv, argv + argc));
}

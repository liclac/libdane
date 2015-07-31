#include "App.h"

int main(int argc, char **argv)
{
	App app;
	return app.run(std::vector<std::string>(argv, argv + argc));
}

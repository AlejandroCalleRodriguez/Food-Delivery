import { BadRequestException} from "@nestjs/common";
import { Args, Mutation, Resolver, Query, Context } from "@nestjs/graphql";
import { RegisterDto } from "./dto/user.dto";
import { RegisterResponse } from "./types/user.types";
import { UsersService } from "./users.service";
import { User } from "./entities/user.entity";
import { Response } from 'express';


@Resolver('User')
// @UseFilters
export class UsersResolver {
    constructor (
        private readonly userService: UsersService) {}

    @Mutation(() => RegisterResponse)
    async register(
        @Args('registerInput') registerDto: RegisterDto,
        @Context() context: { res: Response },
    ): Promise<RegisterResponse> {
        if (!registerDto.name || !registerDto.email || !registerDto.password) {
            throw new BadRequestException('Please fill all the fields');
        }

        const user = await this.userService.register(registerDto, context.res);

        return { user };

    }

    @Query(() => [User])
    async getUsers() {
        return this.userService.getUsers();
    }
}

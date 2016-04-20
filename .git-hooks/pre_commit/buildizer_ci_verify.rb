module Overcommit::Hook::PreCommit
  class BuildizerCiVerify < Base
    def run
      return :fail unless system("buildizer setup --verify-ci")
      :pass
    end
  end
end
